"""
This module defines the LangGraph workflow for the cybersecurity pipeline.
It handles task decomposition, execution, and dynamic task management.
"""

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

# Import scan wrappers
from scan.nmap_scan import NmapScanner
# Import utility modules
from utils.task_manager import TaskManager, Task, TaskStatus
from utils.scope import ScopeValidator
from utils.logger import setup_logger

# Setup logger
logger = logging.getLogger(__name__)

# Define state schema
class AgentState(BaseModel):
    objectives: List[str] = Field(default_factory=list, description="High-level security objectives")
    task_manager: Dict[str, Any] = Field(default_factory=dict, description="Task manager state")
    current_task_id: Optional[str] = Field(default=None, description="ID of the task currently being executed")
    scope_validator: Dict[str, Any] = Field(default_factory=dict, description="Scope enforcer configuration")
    results: Dict[str, Any] = Field(default_factory=dict, description="Results of completed tasks")
    error_log: List[str] = Field(default_factory=list, description="Log of errors encountered during execution")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Conversation history")
    execution_log: List[Dict[str, Any]] = Field(default_factory=list, description="Log of executed actions")
    report: Dict[str, Any] = Field(default_factory=dict, description="Final report")

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
You are an expert cybersecurity analyst. Below are the results of network scans including detailed outputs from nmap.
Use this data to create a comprehensive cybersecurity report that includes:

- Executive Summary
- Methodology
- Detailed Findings (open ports, vulnerabilities, etc.)
- Recommendations
- Technical Details

Present the report in Markdown.

OBJECTIVES:
{objectives}

TARGET SCOPE:
{scope}

EXECUTED TASKS (JSON format):
{tasks}

SCAN RESULTS:
{raw_results}
'''




def extract_json_array(text: str) -> List[Dict[str, Any]]:
    """
    Extracts a JSON array from text, handling various formats.
    """
    # Find the first occurrence of '[' and the last occurrence of ']'
    start = text.find('[')
    end = text.rfind(']') + 1

    if start == -1 or end == 0:
        logger.error("No JSON array found in the text.")
        raise ValueError("No JSON array found in the text.")

    json_array_str = text[start:end]

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

        # Create the workflow graph
        self.workflow = self._build_workflow()

    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow."""
        # Create the graph using the official LangGraph StateGraph
        workflow = StateGraph(AgentState)

        # Define nodes
        workflow.add_node("decompose_tasks", self._decompose_tasks)
        workflow.add_node("select_next_task", self._select_next_task)
        workflow.add_node("check_scope", self._check_scope)
        workflow.add_node("execute_task", self._execute_task)
        workflow.add_node("analyze_results", self._analyze_results)
        workflow.add_node("generate_report", self._generate_report)

        # Add the START edge to define the entrypoint
        workflow.add_edge(START, "decompose_tasks")

        # Define the rest of the edges
        workflow.add_edge("decompose_tasks", "select_next_task")

        workflow.add_conditional_edges(
            "select_next_task",
            self._has_next_task,
            {
                True: "check_scope",
                False: "generate_report"
            }
        )

        workflow.add_conditional_edges(
            "check_scope",
            self._check_scope_condition,  # Using the renamed function
            {
                True: "execute_task",
                False: "select_next_task"
            }
        )

        workflow.add_edge("execute_task", "analyze_results")
        workflow.add_edge("analyze_results", "select_next_task")
        workflow.add_edge("generate_report", END)

        return workflow

    # Renamed function to check scope condition
    def _check_scope_condition(self, state: AgentState) -> bool:
        """Determine if the current task is in scope."""
        task_id = state.current_task_id
        if not task_id:
            return False

        # Rebuild task manager from state
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task:
            return False

        # Check if the task was skipped due to scope issues
        return task.status != TaskStatus.SKIPPED

    def _decompose_tasks(self, state: AgentState) -> AgentState:
        """Decompose high-level objectives into executable tasks."""
        logger.info("Decomposing high-level objectives into tasks")

        # Clear existing tasks if re-decomposing
        self.task_manager = TaskManager()

        # Create scope string representation
        scope_str = "Domains: " + ", ".join(self.scope_validator.domains + self.scope_validator.wildcard_domains)
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        # Create prompt template
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity task planning assistant."),
            HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                objective="\n".join(state.objectives),
                scope=scope_str
            ))
        ])

        chain = prompt | self.llm

        try:
            # Call the LLM
            raw_output = chain.invoke({})

            # Extract content from AIMessage if needed
            if isinstance(raw_output, AIMessage):
                raw_output = raw_output.content

            logger.debug(f"Raw LLM output: {raw_output}")  # Log the raw output

            # Parse the JSON task list
            tasks_list = extract_json_array(raw_output) if isinstance(raw_output, str) else raw_output

            logger.info(f"Tasks list: {tasks_list}")

            # Add tasks to the task manager
            for task_data in tasks_list:
                logger.debug(f"Task data before extraction: {task_data}")  # Log each task data item
                # Extract params correctly using 'params' key (fallback to 'arguments')
                params = task_data.get("params", task_data.get("arguments", {}))

                # Extract depends_on correctly (fallback to 'dependencies')
                depends_on = task_data.get("depends_on", task_data.get("dependencies", []))

                task = Task(
                    id=task_data.get("id", None),  # Use provided ID if available
                    name=task_data.get("name", ""),
                    tool=task_data.get("tool", ""),
                    params=params,  # Use the extracted params
                    description=task_data.get("description", ""),
                    max_retries=task_data.get("max_retries", 3),
                    depends_on=depends_on  # Use the extracted depends_on
                )

                self.task_manager.add_task(task)

            # Update state
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

        # Rebuild task manager from state if needed
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
        """Execute the current task using the appropriate tool."""
        task_id = state.current_task_id
        if not task_id:
            return state

        # Rebuild task manager from state if needed
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task:
            return state

        # Mark the task as running
        task.status = TaskStatus.RUNNING
        task.started_at = self.task_manager.get_current_time()
        self.task_manager.update_task(task)
        logger.info(f"Executing task: {task.name} (ID: {task.id}) with tool: {task.tool}")

        try:
            # Retrieve the appropriate tool instance
            tool = self.tools.get(task.tool)
            if not tool:
                raise ValueError(f"Tool '{task.tool}' not found")

            # Process parameters for different tools
            if task.tool == "nmap":
                params = task.params.copy()

                # Remove the 'version_detection' key if present 
                if "version_detection" in params:
                    params.pop("version_detection")

                # Ensure we have a target
                logger.debug(f"Executing task: {task.name} (ID: {task.id}) with params: {params}")
                if "target" not in params or not params.get("target"):
                    logger.error("Target parameter is missing.")
                    raise ValueError("Target parameter is missing.")

                # Handle target format (string or list)
                if isinstance(params["target"], list):
                    pass
                elif "," in params["target"]:
                    params["target"] = [t.strip() for t in params["target"].split(",")]

                # Set a reasonable timeout if not specified
                if "timeout" not in params:
                    if params.get("scan_type") in ["comprehensive", "vulnerability"]:
                        params["timeout"] = 600
                    elif params.get("scan_type") in ["service", "os_detection"]:
                        params["timeout"] = 300
                    else:
                        params["timeout"] = 180

                # For any port scanning task (non-ping), force the ports to be "1-10000"
                # and ensure that only open ports are shown by adding the "--open" flag.
                if params.get("scan_type", "").lower() != "ping":
                    params["ports"] = "1-10000"
                    if "arguments" in params:
                        if "--open" not in params["arguments"]:
                            params["arguments"] += " --open"
                    else:
                        params["arguments"] = "-sV -sC --open"

                # Option to run with sudo if needed
                if "sudo" in params and isinstance(tool, NmapScanner):
                    tool.sudo = params.pop("sudo")

                logger.info(f"Executing nmap scan with parameters: {params}")
                # Inside _execute_task (already present)
                result = tool.scan(**params)
                print(result)
                # Optionally add a summary if available:
                if hasattr(tool, "get_scan_summary"):
                    try:
                        summary = tool.get_scan_summary(result)
                        result["summary"] = summary
                    except Exception as summary_err:
                        logger.warning(f"Failed to generate scan summary: {str(summary_err)}")

                # Store the result
                task.result = result
                task.status = TaskStatus.COMPLETED
                state.results[task.id] = result


        except Exception as e:
            error_msg = f"Error executing task {task.id} ({task.name}): {str(e)}"
            logger.error(error_msg)
            task.status = TaskStatus.FAILED
            if not hasattr(task, 'errors'):
                task.errors = []
            task.errors.append(error_msg)
            if not hasattr(task, 'retry_count'):
                task.retry_count = 0
            task.retry_count += 1
            max_retries = getattr(task, 'max_retries', 3)
            if task.retry_count < max_retries:
                task.status = TaskStatus.RETRYING
                retry_delay = min(2 ** task.retry_count, 60)
                logger.info(f"Retrying task {task.id} ({task.name}) in {retry_delay}s, attempt {task.retry_count}/{max_retries}")
                if not hasattr(task, 'retry_info'):
                    task.retry_info = []
                task.retry_info.append({
                    "attempt": task.retry_count,
                    "timestamp": self.task_manager.get_current_time(),
                    "error": str(e),
                    "next_retry_delay": retry_delay
                })
            state.error_log.append(error_msg)
        finally:
            self.task_manager.update_task(task)
            state.task_manager = self.task_manager.to_dict()

        return state


    def _has_next_task(self, state: AgentState) -> bool:
        """Check if there's a next task to execute."""
        return state.current_task_id is not None

    def _check_scope(self, state: AgentState) -> AgentState:
        """Check if the current task is within the defined scope."""
        task_id = state.current_task_id
        if not task_id:
            return state

        # Rebuild task manager from state
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task:
            return state

        # Extract target from task parameters
        target = None
        if task.tool == "nmap":
            target = task.params.get("target", "")

        if target:
            # Check if target is in scope
            is_in_scope = self.scope_validator.is_in_scope(target)
            if not is_in_scope:
                logger.warning(f"Task {task.id} ({task.name}) target {target} is out of scope - skipping")
                task.status = TaskStatus.SKIPPED
                task.errors.append("Target is out of scope")
                self.task_manager.update_task(task)
                state.task_manager = self.task_manager.to_dict()

                # Log the scope violation
                violation_log = {
                    "timestamp": self.task_manager.get_current_time(),
                    "task_id": task.id,
                    "task_name": task.name,
                    "target": target,
                    "type": "scope_violation",
                    "message": "Target is out of scope"
                }
                state.execution_log.append(violation_log)

        return state

    def _analyze_results(self, state: AgentState) -> AgentState:
        """Analyze task results and determine if new tasks should be added."""
        task_id = state.current_task_id
        if not task_id or task_id not in state.results:
            return state

        # Rebuild task manager from state
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        task = self.task_manager.get_task(task_id)
        if not task or task.status != TaskStatus.COMPLETED:
            return state

        results = state.results.get(task_id, {})

        logger.info(f"Analyzing results for task {task_id}")

        # Create a summary of current tasks
        current_tasks_summary = []
        for t in self.task_manager.get_all_tasks():
            current_tasks_summary.append({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "tool": t.tool,
                "status": t.status.value
            })

        # Create scope summary
        scope_str = "Domains: " + ", ".join(self.scope_validator.domains + self.scope_validator.wildcard_domains)
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        # Create the prompt
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity analyst."),
            HumanMessage(content=RESULT_ANALYSIS_PROMPT.format(
                task=task.to_dict(),
                results=results,
                current_tasks=current_tasks_summary,
                scope=scope_str
            ))
        ])

        # Parse the output as JSON
        chain = prompt | self.llm | JsonOutputParser()

        # Execute the chain
        try:
            new_tasks = chain.invoke({})

            # Add new tasks to the task manager
            if new_tasks and len(new_tasks) > 0:
                for task_data in new_tasks:
                    # Use 'params' if available, otherwise fallback to 'arguments'
                    params = task_data.get("params", task_data.get("arguments", {}))
                    # Use 'depends_on' if available, otherwise fallback to 'dependencies'
                    depends_on = task_data.get("depends_on", task_data.get("dependencies", []))
                    new_task = Task(
                        name=task_data.get("name", ""),
                        tool=task_data.get("tool", ""),
                        params=params,
                        description=task_data.get("description", ""),
                        depends_on=depends_on
                    )
                    self.task_manager.add_task(new_task)

                # Update the state
                state.task_manager = self.task_manager.to_dict()
                logger.info(f"Added {len(new_tasks)} new tasks based on analysis")
            else:
                logger.info("No new tasks needed based on result analysis")

        except Exception as e:
            error_msg = f"Error analyzing results: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)

        return state

    def _generate_report(self, state: AgentState) -> AgentState:
        logger.info("Generating final security report")

        # Rebuild task manager from state if needed
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        # Collect all task results and build a raw results string
        all_results = {}
        raw_results = ""
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if task:
                all_results[task_id] = {
                    "task": task.to_dict(),
                    "result": result
                }
                # Build a string that includes command, summary, and full output
                raw_results += f"Task {task.name} (ID: {task_id}):\n"
                raw_results += f"Executed Command: {result.get('command', 'N/A')}\n"
                if result.get("summary"):
                    raw_results += f"Scan Summary: {result.get('summary')}\n"
                raw_results += f"Full Output:\n{result.get('stdout', '')}\n\n"

        # Create scope summary
        scope_str = "Domains: " + ", ".join(self.scope_validator.domains + self.scope_validator.wildcard_domains)
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        # Create the report prompt content using the updated prompt template
        report_prompt_content = REPORT_GENERATION_PROMPT.format(
            objectives="\n".join(state.objectives),
            scope=scope_str,
            tasks=[t.to_dict() for t in self.task_manager.get_all_tasks()],
            raw_results=raw_results
        )

        # Optional: Truncate prompt if needed
        max_characters = 20000
        if len(report_prompt_content) > max_characters:
            report_prompt_content = report_prompt_content[:max_characters] + "\n...[truncated]"
            logger.info("Report prompt content truncated to 20,000 characters.")

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity report writer. Please generate a report that does not exceed 5000 tokens."),
            HumanMessage(content=report_prompt_content)
        ])

        logger.debug(f"Final report prompt content: {report_prompt_content[:1000]} ...")

        chain = prompt | self.llm
        try:
            report_result = chain.invoke({}, max_tokens=7000)
            report_content = report_result.content if isinstance(report_result, AIMessage) else report_result

            if not report_content or not report_content.strip():
                report_content = "Report generation failed: The LLM returned empty content. Please check the prompt and try again."
                logger.warning("LLM returned empty report content.")

            report_obj = {
                "content": report_content,
                "timestamp": self.task_manager.get_current_time(),
                "execution_summary": {
                    "total_tasks": len(self.task_manager.get_all_tasks()),
                    "completed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED]),
                    "failed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED]),
                    "skipped_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])
                }
            }

            state.report = report_obj
            logger.info("Final security report generated successfully")
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)
            state.report = {
                "content": "Error generating report",
                "error": str(e),
                "timestamp": self.task_manager.get_current_time()
            }

        return state




    def run(self, objectives: List[str], scope_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run the cybersecurity workflow.

        Args:
            objectives: List of high-level security objectives
            scope_config: Configuration for the scope enforcer

        Returns:
            dict: Workflow results including report
        """
        # Initialize scope enforcer
        self._setup_scope(scope_config)

        # Initialize the state
        initial_state = AgentState(
            objectives=objectives,
            scope_validator={
                "domains": self.scope_validator.domains,
                "wildcard_domains": self.scope_validator.wildcard_domains,
                "ip_ranges": [str(ip) for ip in self.scope_validator.ip_ranges],
                "enabled": self.scope_validator.enabled
            }
        )

        # Run the workflow
        logger.info(f"Starting cybersecurity workflow with objectives: {objectives}")
        try:
            # Compile the workflow first
            compiled_workflow = self.workflow.compile()
            final_state = compiled_workflow.invoke(initial_state)

            # Convert the final state to a dictionary we can return
            if hasattr(final_state, 'dict'):
                final_state_dict = final_state.dict()
            else:
                final_state_dict = {
                    "report": getattr(final_state, "report", {}),
                    "results": getattr(final_state, "results", {}),
                    "execution_log": getattr(final_state, "execution_log", []),
                    "error_log": getattr(final_state, "error_log", [])
                }

            return {
                "report": final_state_dict.get("report", {}),
                "results": final_state_dict.get("results", {}),
                "execution_log": final_state_dict.get("execution_log", []),
                "error_log": final_state_dict.get("error_log", [])
            }

        except Exception as e:
            logger.error(f"Error running workflow: {str(e)}")
            raise RuntimeError(f"Workflow execution failed: {str(e)}")

    def _setup_scope(self, scope_config: Dict[str, Any]) -> None:
        """
        Set up the scope enforcer from configuration.

        Args:
            scope_config: Configuration for the scope enforcer
        """
        # Reset the scope enforcer
        self.scope_validator = ScopeValidator()

        # Add domains
        for domain in scope_config.get("domains", []):
            self.scope_validator.add_domain(domain)

        # Add wildcard domains
        for wildcard in scope_config.get("wildcard_domains", []):
            self.scope_validator.add_wildcard_domain(wildcard)

        # Add IP ranges
        for ip_range in scope_config.get("ip_ranges", []):
            self.scope_validator.add_ip_range(ip_range)

        # Add individual IPs
        for ip in scope_config.get("ips", []):
            self.scope_validator.add_ip(ip)

        # Set enabled status
        self.scope_validator.enabled = scope_config.get("enabled", True)

        logger.info(f"Scope enforcer configured with {len(self.scope_validator.domains)} domains, "
                    f"{len(self.scope_validator.wildcard_domains)} wildcard domains, and "
                    f"{len(self.scope_validator.ip_ranges)} IP ranges")
