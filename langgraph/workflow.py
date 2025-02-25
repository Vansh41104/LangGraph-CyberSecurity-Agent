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
from scans.nmap_scan import NmapScanner
from scans.gobuster_scan import GoBusterScanner
from scans.ffuf_scan import FFUFScanner

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
def get_llm(model="llama-3.3-70b-versatile", temperature=0):
    return ChatGroq(model=model, temperature=temperature)

# Task decomposition prompt - Simplified for efficiency
TASK_DECOMPOSITION_PROMPT = '''
You are an expert cybersecurity analyst. Break down the following high-level security objective into concrete tasks:

OBJECTIVE: {objective}
TARGET SCOPE: {scope}

Available tools:
1. nmap - For network mapping and port scanning
2. gobuster - For directory and file brute-forcing
3. ffuf - For web fuzzing and parameter discovery

Each task should be a JSON object with:
- "id": unique identifier (string)
- "name": descriptive task name (string)
- "description": detailed description (string)
- "tool": tool to use ("nmap", "gobuster", or "ffuf")
- "params": JSON object with tool-specific parameters
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
```json
[
  {
    "id": "unique_id",
    "name": "Descriptive task name", 
    "description": "Detailed description",
    "tool": "tool_name",
    "params": {"arg1": "value1", "arg2": "value2"},
    "depends_on": ["dependency_task_id"]
  }
]
'''

# Report generation prompt - Focused on key details
REPORT_GENERATION_PROMPT = '''
You are an expert cybersecurity analyst. Create a comprehensive security report based on the executed scans.

OBJECTIVES: {objectives}
TARGET SCOPE: {scope}
EXECUTED TASKS: {tasks}
SCAN RESULTS: {results}

Include:
1. Executive Summary
2. Methodology
3. Findings and Vulnerabilities (with severity ratings)
4. Recommendations
5. Technical Details

Format your report in Markdown.
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
            "gobuster": GoBusterScanner(),
            "ffuf": FFUFScanner()
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

    # Add this function with a different name
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
            
            logger.debug(f"Raw LLM output: {raw_output}")
            
            # Parse the JSON task list
            tasks_list = extract_json_array(raw_output) if isinstance(raw_output, str) else raw_output
            
            logger.info(f"Tasks list: {tasks_list}")
            
            # Add tasks to the task manager
            for task_data in tasks_list:
                # Extract params correctly
                params = {}
                if "params" in task_data:
                    params = task_data["params"]
                elif "arguments" in task_data:
                    params = task_data["arguments"]
                
                # Extract depends_on correctly
                depends_on = []
                if "depends_on" in task_data:
                    depends_on = task_data["depends_on"]
                elif "dependencies" in task_data:
                    depends_on = task_data["dependencies"]
                
                task = Task(
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

    def _select_next_task(self, state: AgentState) -> AgentState:
        """Select the next task to execute based on dependencies and status."""
        logger.info("Selecting next task to execute")
        
        # Rebuild task manager from state if needed
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)
        
        # Get the next executable task
        next_task = self.task_manager.get_next_executable_task()
        
        if next_task:
            state.current_task_id = next_task.id
            logger.info(f"Selected task: {next_task.name} (ID: {next_task.id})")
        else:
            state.current_task_id = None
            logger.info("No more tasks to execute")
        
        # Update task manager in state
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
        
        # Extract target from task arguments
        target = None
        if task.tool == "nmap":
            target = task.params.get("target", "")
        elif task.tool == "gobuster":
            target = task.params.get("url", "")
        elif task.tool == "ffuf":
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
    
    def _is_in_scope(self, state: AgentState) -> bool:
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
    
    def _execute_task(self, state: AgentState) -> AgentState:
        """Execute the current task using the appropriate tool."""
        task_id = state.current_task_id
        if not task_id:
            return state
        
        # Rebuild task manager from state
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
            # Get the appropriate tool
            tool = self.tools.get(task.tool)
            if not tool:
                raise ValueError(f"Tool '{task.tool}' not found")
            
            # Execute the tool with the task parameters
            result = None
            if task.tool == "nmap":
                result = tool.scan(**task.params)  # Changed from arguments to params
            elif task.tool == "gobuster":
                result = tool.scan(**task.params)  # Changed from arguments to params
            elif task.tool == "ffuf":
                result = tool.fuzz(**task.params)  # Changed from arguments to params
            else:
                raise ValueError(f"Unknown tool: {task.tool}")
            
            # Store the result
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = self.task_manager.get_current_time()
            
            # Store the result in the state
            state.results[task.id] = result
            
            # Log the execution
            execution_log = {
                "timestamp": self.task_manager.get_current_time(),
                "task_id": task.id,
                "task_name": task.name,
                "tool": task.tool,
                "arguments": task.params,  # Changed from arguments to params
                "status": "completed",
                "duration": (task.completed_at - task.started_at) if task.completed_at and task.started_at else None
            }
            state.execution_log.append(execution_log)
            
            logger.info(f"Task {task.id} ({task.name}) completed successfully")
        
        except Exception as e:
            # Handle task execution failure
            error_msg = f"Error executing task {task.id} ({task.name}): {str(e)}"
            logger.error(error_msg)
            
            task.status = TaskStatus.FAILED
            
            # Make sure the errors attribute exists
            if not hasattr(task, 'errors'):
                task.errors = []
                
            task.errors.append(error_msg)
            
            # Make sure retry_count exists
            if not hasattr(task, 'retry_count'):
                task.retry_count = 0
            
            task.retry_count += 1
            
            # Retry logic
            if task.retry_count < task.max_retries:
                task.status = TaskStatus.RETRYING
                logger.info(f"Retrying task {task.id} ({task.name}), attempt {task.retry_count + 1}/{task.max_retries}")
            
            # Log the failure
            execution_log = {
                "timestamp": self.task_manager.get_current_time(),
                "task_id": task.id,
                "task_name": task.name,
                "tool": task.tool,
                "arguments": task.params,  # Changed from arguments to params
                "status": "failed",
                "error": str(e),
                "retry_count": task.retry_count
            }
            state.execution_log.append(execution_log)
            state.error_log.append(error_msg)
        
        finally:
            # Update the task in the task manager
            self.task_manager.update_task(task)
            state.task_manager = self.task_manager.to_dict()
        
        return state

    def _analyze_results(self, state: AgentState) -> AgentState:
        """Analyze task results and determine if new tasks should be added."""
        task_id = state.current_task_id
        if not task_id or task_id not in state.results:
            return state
        
        # Get the current task and its results
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
                    # Use params consistently instead of switching between params/arguments
                    new_task = Task(
                        name=task_data.get("name", ""),
                        tool=task_data.get("tool", ""),
                        params=task_data.get("arguments", {}),  # or 'params' if your incoming data uses that key
                        description=task_data.get("description", ""),
                        depends_on=task_data.get("dependencies", [])
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
        """Generate a final security report."""
        logger.info("Generating final security report")
        
        # Rebuild task manager from state
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)
            
        # Collect all task results
        all_results = {}
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if task:
                all_results[task_id] = {
                    "task": task.to_dict(),
                    "result": result
                }
        
        # Create scope summary
        scope_str = "Domains: " + ", ".join(self.scope_validator.domains + self.scope_validator.wildcard_domains)
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)
        
        # Create prompt for report generation
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity report writer."),
            HumanMessage(content=REPORT_GENERATION_PROMPT.format(
                objectives="\n".join(state.objectives),
                scope=scope_str,
                tasks=[t.to_dict() for t in self.task_manager.get_all_tasks()],
                results=all_results
            ))
        ])
        
        # Generate the report
        chain = prompt | self.llm
        
        try:
            report_result = chain.invoke({})
            report_content = report_result.content if isinstance(report_result, AIMessage) else report_result
            
            # Create a report object and set it directly on the state
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
            
            # Assign the report to the state - this needs to work with different state representations
            if hasattr(state, '__setattr__'):
                # If state supports direct attribute assignment
                state.__setattr__('report', report_obj)
            else:
                # Otherwise, try dictionary-style assignment
                state.report = report_obj
                
            logger.info("Final security report generated successfully")
        
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)
            
            report_obj = {
                "content": "Error generating report",
                "error": str(e),
                "timestamp": self.task_manager.get_current_time()
            }
            
            # Same assignment logic as above
            if hasattr(state, '__setattr__'):
                state.__setattr__('report', report_obj)
            else:
                state.report = report_obj
        
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