import json
import logging
import uuid
from typing import Dict, List, Any, Tuple, Optional, Callable
from pydantic import BaseModel, Field

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_groq import ChatGroq

from langgraph.graph import StateGraph, END, START
import datetime
import re
import os


# Import scan wrappers
from scan.nmap_scan import NmapScanner
# Import utility modules
from utils.task_manager import TaskManager, Task, TaskStatus
from utils.scope import ScopeValidator
from utils.logger import setup_logger

# Setup logger
logger = logging.getLogger(__name__)

# Define state schema
# Define state schema
class AgentState(BaseModel):
    objectives: List[str] = Field(default_factory=list)
    scope_validator: Dict[str, Any] = Field(default_factory=dict)
    task_manager: Dict[str, Any] = Field(default_factory=dict)
    results: Dict[str, Any] = Field(default_factory=dict)
    execution_log: List[Dict[str, Any]] = Field(default_factory=list)
    error_log: List[str] = Field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
    current_task_id: Optional[str] = None

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

# Initialize the LLM
def get_llm(model="gemma2-9b-it", temperature=0):
    return ChatGroq(model=model, temperature=temperature)


# Task decomposition prompt - Updated for proper parameter formatting
TASK_DECOMPOSITION_PROMPT = '''
You are an expert cybersecurity analyst. Break down the following high-level security objective into concrete tasks:

OBJECTIVE: {objective}
TARGET SCOPE: {scope}

Available tool:
1. nmap - For network mapping and port scanning

For nmap tasks, please provide parameters in this format:
- For simple ping scan: {{"target": "domain.com", "scan_type": "ping"}}
- For port scan: {{"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}}
- For service detection: {{"target": "domain.com", "scan_type": "syn", "ports": "1-1000", "version_detection": true}}

Each task should be a JSON object with:
- "id": unique identifier (string)
- "name": descriptive task name (string)
- "description": detailed description (string)
- "tool": tool to use ("nmap")
- "params": JSON object with tool-specific parameters (use the format shown above, **including the target parameter**)
- "depends_on": array of task IDs this task depends on

Return a JSON array of task objects. No extra text, just valid JSON.
'''

RESULT_ANALYSIS_PROMPT = '''
You are an expert cybersecurity analyst. Review these scan results and determine follow-up actions.

ORIGINAL TASK: {task}
SCAN RESULTS: {results}
CURRENT TASKS: {current_tasks}
TARGET SCOPE: {scope}

Determine if any new tasks should be added. Focus on:
1. Investigating open ports and services
2. Following up on potential vulnerabilities
3. Confirming uncertain results

For each new task, provide:
[
  {
    "id": "unique_id",
    "name": "Descriptive task name",
    "description": "Detailed description",
    "tool": "nmap",
    "params": {"target": "domain.com", "scan_type": "syn", "ports": "1-1000"},
    "depends_on": []
  }
]
'''

# Report generation prompt - Focused on key details
REPORT_GENERATION_PROMPT = '''
Please generate a complete security report based on the following information:

OBJECTIVES:
{"\n".join(state.objectives)}

TARGET SCOPE:
{scope_str}

EXECUTED TASKS:
{len(self.task_manager.get_all_tasks())} tasks were executed, with {len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED])} completed successfully.

KEY FINDINGS:
{raw_results}

Please structure the report with:
1. Executive Summary
2. Methodology
3. Key Findings
4. Recommendations
5. Technical Details
'''



def extract_json_array(text: str) -> List[Dict[str, Any]]:
    """
    Extracts a JSON array from text, handling various formats more robustly.
    """
    # Use regex to find a JSON array. This pattern matches the first occurrence of a [ ... ] block.
    pattern = re.compile(r'(\[.*\])', re.DOTALL)
    match = pattern.search(text)
    if not match:
        logger.error("No JSON array found in the text.")
        raise ValueError("No JSON array found in the text.")

    json_array_str = match.group(1).strip()
    logger.debug(f"Extracted JSON array string: {json_array_str}")

    try:
        json_array = json.loads(json_array_str)
        if isinstance(json_array, list):
            return json_array
        else:
            logger.error("Extracted JSON is not a list.")
            raise ValueError("Extracted JSON is not a list.")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error: {e}")
        raise ValueError(f"JSON decoding error: {e}")
class CybersecurityWorkflow:
    """
    Manages the LangGraph workflow for cybersecurity tasks.
    """

    def __init__(self, llm=None):
        """Initialize the workflow with tools and LLM."""
        self.llm = llm or get_llm()
        self.task_manager = TaskManager()
        self.scope_validator = ScopeValidator()

        # Initialize security tools
        self.tools = {
            "nmap": NmapScanner(),
        }

        # Create the workflow graph with an increased recursion limit.
        self.workflow = self._build_workflow()

    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow."""
        # Option 2: Otherwise, create the graph normally and then set the recursion_limit attribute.
        workflow = StateGraph(AgentState)
        
        # Define nodes
        workflow.add_node("decompose_tasks", self._decompose_tasks)
        workflow.add_node("select_next_task", self._select_next_task)
        workflow.add_node("check_scope", self._check_scope)
        workflow.add_node("execute_task", self._execute_task)
        workflow.add_node("analyze_results", self._analyze_results)
        workflow.add_node("generate_report", self._generate_report)

        # Add edges
        workflow.add_edge(START, "decompose_tasks")
        workflow.add_edge("decompose_tasks", "select_next_task")
        workflow.add_conditional_edges(
            "select_next_task",
            self._has_next_task,
            {
                True: "check_scope",
                False: "generate_report"  # When no tasks remain, generate report
            }
        )
        workflow.add_conditional_edges(
            "check_scope",
            self._check_scope_condition,
            {
                True: "execute_task",
                False: "select_next_task"
            }
        )
        workflow.add_edge("execute_task", "analyze_results")
        workflow.add_edge("analyze_results", "select_next_task")
        workflow.add_edge("generate_report", END)

        # Increase the recursion limit by setting a custom attribute.
        setattr(workflow, "recursion_limit", 50)

        return workflow

    def _check_scope_condition(self, state: AgentState) -> bool:
        """Determine if the current task is in scope."""
        task_id = state.current_task_id
        if not task_id:
            return False

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task:
            return False

        return task.status != TaskStatus.SKIPPED

    def _decompose_tasks(self, state: AgentState) -> AgentState:
        logger.info("Decomposing high-level objectives into tasks")
        self.task_manager = TaskManager()

        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity task planning assistant."),
            HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                objective="\n".join(state.objectives),
                scope=scope_str
            ))
        ])

        chain = prompt | self.llm

        try:
            raw_output = chain.invoke({})
            if hasattr(raw_output, "content"):
                raw_output = raw_output.content

            logger.debug(f"Raw LLM output: {raw_output}")

            # Parse the output into a list of tasks
            tasks_list = extract_json_array(raw_output) if isinstance(raw_output, str) else raw_output
            if not isinstance(tasks_list, list):
                raise ValueError(f"Decomposed tasks output is not a list: {tasks_list}")

            # Limit to first 10 tasks if needed
            if len(tasks_list) > 10:
                logger.info(f"Limiting tasks: Only the first 10 of {len(tasks_list)} tasks will be processed")
                tasks_list = tasks_list[:10]

            logger.info(f"Tasks list: {tasks_list}")

            for task_data in tasks_list:
                # Only process if task_data is a dict
                if not isinstance(task_data, dict):
                    logger.warning(f"Skipping invalid task data (expected dict, got {type(task_data)}): {task_data}")
                    continue
                task_id = task_data.get("id")
                if not task_id:
                    task_id = str(uuid.uuid4())
                task = Task(
                    id=task_id,
                    name=task_data.get("name", ""),
                    tool=task_data.get("tool", ""),
                    params=task_data.get("params", task_data.get("arguments", {})),
                    description=task_data.get("description", ""),
                    max_retries=task_data.get("max_retries", 3),
                    depends_on=task_data.get("depends_on", task_data.get("dependencies", []))
                )
                self.task_manager.add_task(task)

            state.task_manager = self.task_manager.to_dict()
            logger.info(f"Created {len(tasks_list)} tasks from objectives")
        except Exception as e:
            logger.error(f"Error decomposing tasks: {str(e)}")
            state.error_log.append(f"Error decomposing tasks: {str(e)}")
        return state


    def _get_next_executable_task(self) -> Optional[Task]:
        """
        Returns the next pending task whose dependencies are all completed.
        """
        for task in self.task_manager.get_all_tasks():
            if task.status == TaskStatus.PENDING:
                deps_satisfied = True
                for dep_id in task.depends_on:
                    dep_task = self.task_manager.get_task(dep_id)
                    if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                        deps_satisfied = False
                        break
                if deps_satisfied:
                    return task
        return None

    def _select_next_task(self, state: AgentState) -> AgentState:
        """Select the next task to execute based on dependencies and status."""
        logger.info("Selecting next task to execute")
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        next_task = self._get_next_executable_task()
        if next_task:
            state.current_task_id = next_task.id
            logger.info(f"Selected task: {next_task.name} (ID: {next_task.id})")
        else:
            state.current_task_id = None
            logger.info("No more tasks to execute")

        state.task_manager = self.task_manager.to_dict()
        return state

    def _execute_task(self, state: AgentState) -> AgentState:
        task_id = state.current_task_id
        if not task_id:
            logger.info("No task ID provided, skipping execution")
            return state

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)
        
        task = self.task_manager.get_task(task_id)
        if not task:
            logger.warning(f"Task {task_id} not found, skipping execution")
            return state

        task.status = TaskStatus.RUNNING
        task.started_at = self.task_manager.get_current_time()
        self.task_manager.update_task(task)
        logger.info(f"Executing task: {task.name} (ID: {task.id}) with tool: {task.tool}")

        try:
            if not hasattr(task, 'errors'):
                task.errors = []

            tool = self.tools.get(task.tool)
            if not tool:
                raise ValueError(f"Tool '{task.tool}' not found")

            params = task.params.copy()
            if "target" not in params or not params.get("target"):
                logger.error("Target parameter is missing.")
                raise ValueError("Target parameter is missing.")

            if isinstance(params["target"], str) and "," in params["target"]:
                params["target"] = [t.strip() for t in params["target"].split(",")]

            if task.params.get("version_detection", False):
                if "arguments" in params:
                    params["arguments"] += " -sV"
                else:
                    params["arguments"] = "-sV"

            if "timeout" not in params:
                params["timeout"] = 180

            if "sudo" in params and isinstance(tool, NmapScanner):
                tool.sudo = params.pop("sudo")

            logger.info(f"Executing nmap scan with parameters: {params}")
            result = tool.scan(**params)
            self.debug_nmap_results(result, task.id)

            task.result = result
            task.status = TaskStatus.COMPLETED
            state.results[task.id] = result

            logger.info(f"Completed task: {task.name} (ID: {task.id})")
        except Exception as e:
            error_msg = f"Error executing task {task.id} ({task.name}): {str(e)}"
            logger.error(error_msg)
            task.status = TaskStatus.FAILED
            task.errors.append(error_msg)
            task.retry_count = getattr(task, 'retry_count', 0) + 1
            if task.retry_count < getattr(task, 'max_retries', 3):
                task.status = TaskStatus.RETRYING
                retry_delay = min(2 ** task.retry_count, 60)
                logger.info(f"Retrying task {task.id} ({task.name}) in {retry_delay}s, attempt {task.retry_count}")
            state.error_log.append(error_msg)
        finally:
            self.task_manager.update_task(task)
            state.task_manager = self.task_manager.to_dict()
        return state


    def debug_nmap_results(self, result: Any, task_id: str) -> Any:
        """Debug helper to ensure nmap results are properly captured."""
        os.makedirs("debug", exist_ok=True)
        with open(f"debug/nmap_result_{task_id}.json", "w") as f:
            try:
                json.dump(result, f, indent=2)
            except TypeError:
                f.write(str(result))

        if isinstance(result, dict) and "stdout" in result:
            logger.info(f"Nmap stdout: {result['stdout'][:500]}...")

        if isinstance(result, dict):
            logger.info(f"Result keys: {list(result.keys())}")
            if "hosts" in result:
                for host in result["hosts"]:
                    if "ports" in host:
                        logger.info(f"Found {len(host['ports'])} ports for host")
                        for port in host["ports"]:
                            logger.info(f"Port details: {port}")

        return result

    def _has_next_task(self, state: AgentState) -> bool:
        """Check if there's a next task to execute."""
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        pending_tasks = [t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.PENDING]
        has_next = len(pending_tasks) > 0

        logger.info(f"Has next task check: {has_next} (found {len(pending_tasks)} pending tasks)")
        return has_next

    def _check_scope(self, state: AgentState) -> AgentState:
        """Check if the current task is within the defined scope."""
        task_id = state.current_task_id
        if not task_id:
            return state

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task:
            return state

        target = None
        if task.tool == "nmap":
            target = task.params.get("target", "")

        if target:
            is_in_scope = self.scope_validator.is_in_scope(target)
            if not is_in_scope:
                logger.warning(f"Task {task.id} ({task.name}) target {target} is out of scope - skipping")
                task.status = TaskStatus.SKIPPED
                if not hasattr(task, 'errors'):
                    task.errors = []
                task.errors.append("Target is out of scope")
                self.task_manager.update_task(task)
                state.task_manager = self.task_manager.to_dict()

                violation_log = {
                    "timestamp": self.task_manager.get_current_time().isoformat(),
                    "task_id": task.id,
                    "task_name": task.name,
                    "target": target,
                    "type": "scope_violation",
                    "message": "Target is out of scope"
                }
                state.execution_log.append(violation_log)

        return state

    def _analyze_results(self, state: AgentState) -> AgentState:
        """Analyze the results of the executed task and optionally add follow-up tasks."""
        task_id = state.current_task_id
        if not task_id:
            return state

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task or task.status != TaskStatus.COMPLETED:
            return state

        results = state.results.get(task_id)
        if not results:
            state.results[task_id] = {"status": "no_results", "timestamp": self.task_manager.get_current_time().isoformat()}
            return state

        logger.info(f"Analyzing results for task {task_id}")
        logger.info(f"Result type: {type(results)}, content preview: {str(results)[:200]}")

        if isinstance(results, dict):
            logger.info(f"Result keys: {list(results.keys())}")
            if "hosts" in results:
                for host in results["hosts"]:
                    if "ports" in host and host["ports"]:
                        logger.info(f"Found {len(host['ports'])} ports for host")
                        for port in host["ports"]:
                            logger.info(f"Port details: {port}")
                    else:
                        logger.info("No port information found in host data")

        current_tasks_summary = []
        for t in self.task_manager.get_all_tasks():
            current_tasks_summary.append({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "tool": t.tool,
                "status": t.status.value
            })

        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity analyst."),
            HumanMessage(content=RESULT_ANALYSIS_PROMPT.format(
                task=task.to_dict(),
                results=results,
                current_tasks=current_tasks_summary,
                scope=scope_str
            ))
        ])

        try:
            chain = prompt | self.llm
            analysis_result = chain.invoke({})
            analysis_text = analysis_result.content if hasattr(analysis_result, "content") else str(analysis_result)

            logger.info(f"Analysis result: {analysis_text[:200]}...")

            # Attach analysis to the task result
            if task.result:
                if isinstance(task.result, dict):
                    task.result['analysis'] = analysis_text
                else:
                    task.result = {'original': task.result, 'analysis': analysis_text}

            # Extract new tasks from the analysis output
            try:
                new_tasks = extract_json_array(analysis_text)
                if new_tasks and len(new_tasks) > 0:
                    existing_count = len(self.task_manager.get_all_tasks())
                    remaining_slots = max(0, 10 - existing_count)
                    if remaining_slots <= 0:
                        logger.info("Task limit reached (10 tasks). No new tasks will be added.")
                    else:
                        logger.info(f"Adding up to {remaining_slots} new tasks from analysis")
                        for task_data in new_tasks[:remaining_slots]:
                            params = task_data.get("params", task_data.get("arguments", {}))
                            depends_on = task_data.get("depends_on", task_data.get("dependencies", []))
                            new_task = Task(
                                id=task_data.get("id") or str(uuid.uuid4()),
                                name=task_data.get("name", ""),
                                tool=task_data.get("tool", ""),
                                params=params,
                                description=task_data.get("description", ""),
                                depends_on=depends_on
                            )
                            self.task_manager.add_task(new_task)

                        state.task_manager = self.task_manager.to_dict()
                        logger.info(f"Added {min(len(new_tasks), remaining_slots)} new tasks based on analysis")
                else:
                    logger.info("No new tasks needed based on result analysis")
            except Exception as json_err:
                logger.warning(f"Could not extract JSON tasks from analysis: {str(json_err)}")

        except Exception as e:
            error_msg = f"Error analyzing results: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)

        self.task_manager.update_task(task)
        state.task_manager = self.task_manager.to_dict()

        return state

    def _generate_report(self, state: AgentState) -> AgentState:
        """Generate the final security report."""
        logger.info("Generating final security report")

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        raw_results = []
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if not task:
                continue
            raw_results.append(f"Task {task.name} (ID: {task.id}): {str(result)}")

        raw_results_str = "\n\n".join(raw_results)

        state["report"] = {
            "content": "## Preliminary Security Report\n\nGenerating detailed analysis...",
            "timestamp": self.task_manager.get_current_time().isoformat(),
            "execution_summary": {
                "total_tasks": len(self.task_manager.get_all_tasks()),
                "completed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED]),
                "failed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED]),
                "skipped_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])
            }
        }

        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity report generator. Produce a plain text report with markdown headings."),
                HumanMessage(content=f"""Generate a detailed security assessment report in plain text. The report must include the following sections, each starting with a markdown heading (e.g., "#"):

# Executive Summary
# Methodology
# Key Findings
# Recommendations
# Technical Details

**Important:**
- Do not output any JSON, code, or raw key-value pairs.
- Do not include any lines that look like raw JSON (e.g., lines starting with 'id').
- Output only the complete report in plain text with markdown formatting.

Objectives: {' '.join(state.objectives)}
Scope: {scope_str}
Findings: {raw_results_str}

Please output only the final report.
""")
            ])

            chain = prompt | self.llm
            report_content = chain.invoke({})
            report_content = report_content.content if hasattr(report_content, "content") else str(report_content)

            logger.info(f"Raw report content: {report_content}")

            report_content = report_content.strip()

            try:
                parsed = json.loads(report_content)
                if isinstance(parsed, dict) and "content" in parsed:
                    logger.info("LLM returned a JSON object; extracting the 'content' key.")
                    report_content = parsed["content"].strip()
            except json.JSONDecodeError:
                pass

            if not report_content.startswith("#"):
                idx = report_content.find("#")
                if idx != -1:
                    report_content = report_content[idx:].strip()
                else:
                    raise ValueError("Report content does not appear to be in the expected format.")

            state["report"] = {
                "content": report_content,
                "timestamp": self.task_manager.get_current_time().isoformat(),
                "raw_findings": raw_results_str,
                "execution_summary": {
                    "total_tasks": len(self.task_manager.get_all_tasks()),
                    "completed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED]),
                    "failed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED]),
                    "skipped_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])
                }
            }

            logger.info("Report generated successfully")

        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            state.error_log.append(f"Error generating report: {str(e)}")
            logger.info("Using fallback report due to error")

        if "report" not in state or not state["report"]:
            fallback_error = state.error_log[-1] if state.error_log else "Unknown error"
            logger.warning("Report still missing after generation attempt, creating emergency fallback")
            state["report"] = {
                "content": f"# Security Assessment Report\n\n## Raw Findings\n{raw_results_str}\n\n## Error\nAn error occurred while generating the detailed report: {fallback_error}",
                "timestamp": self.task_manager.get_current_time().isoformat(),
                "raw_findings": raw_results_str,
                "execution_summary": {
                    "total_tasks": len(self.task_manager.get_all_tasks()),
                    "completed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED]),
                    "failed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED]),
                    "skipped_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])
                }
            }

        return state

    def run(self, objectives: List[str], scope_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the cybersecurity workflow.

        Args:
            objectives: List of high-level security objectives
            scope_config: Configuration for the scope enforcer

        Returns:
            dict: Workflow results including report, results, execution log, and error log
        """
        self._setup_scope(scope_config)

        initial_state = AgentState(
            objectives=objectives,
            scope_validator={
                "domains": self.scope_validator.domains,
                "wildcard_domains": self.scope_validator.wildcard_domains,
                "ip_ranges": [str(ip) for ip in self.scope_validator.ip_ranges],
                "enabled": self.scope_validator.enabled
            }
        )
        initial_state["report"] = None
        initial_state["results"] = {}
        initial_state["execution_log"] = []
        initial_state["error_log"] = []

        logger.info(f"Starting cybersecurity workflow with objectives: {objectives}")

        try:
            compiled_workflow = self.workflow.compile()
            # Instead of passing recursion_limit to invoke(),
            # set the attribute on the compiled workflow.
            compiled_workflow.recursion_limit = 50

            final_state = compiled_workflow.invoke(initial_state)

            if "results" not in final_state:
                final_state["results"] = {}
            if "execution_log" not in final_state:
                final_state["execution_log"] = []
            if "error_log" not in final_state:
                final_state["error_log"] = []

            if "report" not in final_state or not final_state["report"]:
                logger.warning("No report found in final state, creating a basic report")
                final_state["report"] = {
                    "content": "## Security Assessment Report\n\nThe security assessment was completed, but no detailed report could be generated.",
                    "timestamp": self.task_manager.get_current_time().isoformat()
                }

            logger.info(f"Final report state: {'report' in final_state and final_state['report'] is not None}")

            return {
                "report": final_state["report"],
                "results": final_state["results"],
                "execution_log": final_state["execution_log"],
                "error_log": final_state["error_log"]
            }

        except Exception as e:
            logger.error(f"Error running workflow: {str(e)}")
            return {
                "report": {
                    "content": f"## Error Report\n\nThe security workflow failed with error: {str(e)}",
                    "timestamp": self.task_manager.get_current_time().isoformat()
                },
                "error_log": [f"Workflow execution failed: {str(e)}"],
                "results": {},
                "execution_log": []
            }

    def _setup_scope(self, scope_config: Dict[str, Any]) -> None:
        """
        Set up the scope enforcer from configuration.

        Args:
            scope_config: Configuration for the scope enforcer
        """
        self.scope_validator = ScopeValidator()

        for domain in scope_config.get("domains", []):
            self.scope_validator.add_domain(domain)

        for wildcard in scope_config.get("wildcard_domains", []):
            self.scope_validator.add_wildcard_domain(wildcard)

        for ip_range in scope_config.get("ip_ranges", []):
            self.scope_validator.add_ip_range(ip_range)

        for ip in scope_config.get("ips", []):
            self.scope_validator.add_ip(ip)

        self.scope_validator.enabled = scope_config.get("enabled", True)

        logger.info(f"Scope enforcer configured with {len(self.scope_validator.domains)} domains, "
                    f"{len(self.scope_validator.wildcard_domains)} wildcard domains, and "
                    f"{len(self.scope_validator.ip_ranges)} IP ranges")

    def _serialize_datetime(self, obj: Any) -> Any:
        """Helper function to serialize datetime objects for JSON."""
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")