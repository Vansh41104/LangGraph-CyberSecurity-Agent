"""
This module defines the LangGraph workflow for the cybersecurity pipeline.
It handles task decomposition, execution, and dynamic task management.
"""

import logging
import uuid
from typing import Dict, List, Any, Tuple, Optional, Callable
from pydantic import BaseModel, Field

from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI

from langgraph.graph import StateGraph, END
import langgraph.prebuilt as prebuilt

from utils.task_manager import TaskManager, Task, TaskStatus
from utils.scope import ScopeValidator
from utils.logger import setup_logger

# Import scan wrappers
from scans.nmap_scan import NmapScanner
from scans.gobuster_scan import GoBusterScanner
from scans.ffuf_scan import FFUFScanner

# Setup logger
logger = logging.getLogger(__name__)

# Define state schema
class AgentState(BaseModel):
    """State schema for the agent workflow."""
    objectives: List[str] = Field(default_factory=list, description="High-level security objectives")
    task_manager: Dict[str, Any] = Field(default_factory=dict, description="Task manager state")
    current_task_id: Optional[str] = Field(default=None, description="ID of the task currently being executed")
    scope_enforcer: Dict[str, Any] = Field(default_factory=dict, description="Scope enforcer configuration")
    results: Dict[str, Any] = Field(default_factory=dict, description="Results of completed tasks")
    error_log: List[str] = Field(default_factory=list, description="Log of errors encountered during execution")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Conversation history")
    execution_log: List[Dict[str, Any]] = Field(default_factory=list, description="Log of executed actions")
    report: Dict[str, Any] = Field(default_factory=dict, description="Final report")

# Initialize the LLM
def get_llm(model="gpt-4-turbo", temperature=0):
    return ChatOpenAI(model=model, temperature=temperature)

# Task decomposition prompt
TASK_DECOMPOSITION_PROMPT = '''
You are an expert cybersecurity analyst. Your job is to break down high-level security objectives into a series of concrete tasks that can be executed by security tools.

OBJECTIVE: {objective}

TARGET SCOPE:
{scope}

Available tools:
1. nmap - For network mapping and port scanning
2. gobuster - For directory and file brute-forcing
3. ffuf - For web fuzzing and parameter discovery

Each task should include:
- A descriptive name
- The tool to use
- Specific arguments for the tool
- Dependencies on other tasks (if any)

The tasks should be executed in a logical order, with dependencies clearly specified.

Provide your answer as a JSON list of tasks, each with the following structure:
```json
[
  {
    "id": "unique_id",
    "name": "Descriptive task name",
    "description": "Detailed description of what this task does",
    "tool": "tool_name",
    "arguments": {
      "arg1": "value1",
      "arg2": "value2"
    },
    "dependencies": []
  }
]
```
'''

# Result analysis prompt
RESULT_ANALYSIS_PROMPT = '''
You are an expert cybersecurity analyst. Review the results of a security scan and determine what follow-up actions should be taken.

ORIGINAL TASK:
{task}

SCAN RESULTS:
{results}

CURRENT TASKS:
{current_tasks}

TARGET SCOPE:
{scope}

Based on these results, determine if any new tasks should be added to the workflow. Focus on:
1. Investigating open ports, services, or findings from the scan
2. Following up on potential vulnerabilities
3. Confirming any uncertain results with additional scans

For each new task you recommend, include:
- A descriptive name
- The tool to use
- Specific arguments for the tool
- Dependencies on previous tasks

Provide your answer as a JSON list of new tasks, each with the following structure:
```json
[
  {
    "id": "unique_id",
    "name": "Descriptive task name", 
    "description": "Detailed description of what this task does",
    "tool": "tool_name",
    "arguments": {
      "arg1": "value1",
      "arg2": "value2" 
    },
    "dependencies": ["dependency_task_id"]
  }
]
```

If no new tasks are needed, return an empty list: []
'''

# Report generation prompt
REPORT_GENERATION_PROMPT = '''
You are an expert cybersecurity analyst. Create a comprehensive security report based on the executed security scans and their results.

OBJECTIVES:
{objectives}

TARGET SCOPE:
{scope}

EXECUTED TASKS:
{tasks}

SCAN RESULTS:
{results}

Your report should include:
1. Executive Summary
2. Methodology
3. Findings and Vulnerabilities
4. Recommendations
5. Technical Details

For each finding, indicate the severity (Critical, High, Medium, Low, Informational) and provide remediation steps.

Format your report in Markdown.
'''

class CybersecurityWorkflow:
    """
    Manages the LangGraph workflow for cybersecurity tasks.
    """
    
    def __init__(self, llm=None):
        """Initialize the workflow with tools and LLM."""
        self.llm = llm or get_llm()
        self.task_manager = TaskManager()
        self.scope_enforcer = ScopeEnforcer()
        
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
        # Create the graph
        workflow = StateGraph(AgentState)
        
        # Define nodes
        workflow.add_node("decompose_tasks", self._decompose_tasks)
        workflow.add_node("select_next_task", self._select_next_task)
        workflow.add_node("check_scope", self._check_scope)
        workflow.add_node("execute_task", self._execute_task)
        workflow.add_node("analyze_results", self._analyze_results)
        workflow.add_node("generate_report", self._generate_report)
        
        # Define edges
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
            self._is_in_scope,
            {
                True: "execute_task",
                False: "select_next_task"  # Skip task if it's not in scope
            }
        )
        workflow.add_edge("execute_task", "analyze_results")
        workflow.add_edge("analyze_results", "select_next_task")
        workflow.add_edge("generate_report", END)
        
        return workflow
    
    def _decompose_tasks(self, state: AgentState) -> AgentState:
        """Decompose high-level objectives into executable tasks."""
        logger.info("Decomposing high-level objectives into tasks")
        
        # Create prompt with objectives and scope
        scope_str = "Domains: " + ", ".join(self.scope_enforcer.domains + self.scope_enforcer.wildcard_domains)
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_enforcer.ip_ranges)
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity task planning assistant."),
            HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                objective="\n".join(state.objectives),
                scope=scope_str
            ))
        ])
        
        # Parse the output as JSON
        chain = prompt | self.llm | JsonOutputParser()
        
        # Execute the chain
        tasks_list = chain.invoke({})
        
        # Add tasks to the task manager
        for task_data in tasks_list:
            task = Task(
                id=task_data.get("id", str(uuid.uuid4())),
                name=task_data.get("name", ""),
                description=task_data.get("description", ""),
                tool=task_data.get("tool", ""),
                arguments=task_data.get("arguments", {}),
                dependencies=task_data.get("dependencies", [])
            )
            self.task_manager.add_task(task)
        
        # Update the state
        state.task_manager = self.task_manager.to_dict()
        
        # Log the tasks
        logger.info(f"Created {len(tasks_list)} tasks from objectives")
        
        return state
    
    def _select_next_task(self, state: AgentState) -> AgentState:
        """Select the next task to execute based on dependencies and status."""
        logger.info("Selecting next task to execute")
        
        # Rebuild task manager from state if needed
        if hasattr(state, "task_manager") and isinstance(state.task_manager, dict):
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
        
        # Rebuild task manager from state if needed
        if hasattr(state, "task_manager") and isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)
        
        task = self.task_manager.get_task(task_id)
        if not task:
            return state
        
        # Extract target from task arguments
        target = None
        if task.tool == "nmap":
            target = task.arguments.get("target", "")
        elif task.tool == "gobuster":
            target = task.arguments.get("url", "")
        elif task.tool == "ffuf":
            target = task.arguments.get("target", "")
        
        if target:
            # Check if target is in scope
            is_in_scope = self.scope_enforcer.is_in_scope(target)
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
        
        # Check task status in task manager
        task_dict = state.task_manager.get("tasks", {}).get(task_id, {})
        status = task_dict.get("status", "")
        
        # If the task was skipped due to scope issues, return False
        return status != TaskStatus.SKIPPED.value
    
    def _execute_task(self, state: AgentState) -> AgentState:
        """Execute the current task using the appropriate tool."""
        task_id = state.current_task_id
        if not task_id:
            return state
        
        # Rebuild task manager from state if needed
        if hasattr(state, "task_manager") and isinstance(state.task_manager, dict):
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
            
            # Execute the tool with the task arguments
            if task.tool == "nmap":
                result = tool.scan(**task.arguments)
            elif task.tool == "gobuster":
                result = tool.scan(**task.arguments)
            elif task.tool == "ffuf":
                result = tool.fuzz(**task.arguments)
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
                "arguments": task.arguments,
                "status": "completed",
                "duration": task.completed_at - task.started_at if task.completed_at and task.started_at else None
            }
            state.execution_log.append(execution_log)
            
            logger.info(f"Task {task.id} ({task.name}) completed successfully")
        
        except Exception as e:
            # Handle task execution failure
            error_msg = f"Error executing task {task.id} ({task.name}): {str(e)}"
            logger.error(error_msg)
            
            task.status = TaskStatus.FAILED
            task.errors.append(error_msg)
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
                "arguments": task.arguments,
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
        task_dict = state.task_manager.get("tasks", {}).get(task_id, {})
        results = state.results.get(task_id, {})
        
        # Only analyze results for completed tasks
        if task_dict.get("status") != TaskStatus.COMPLETED.value:
            return state
        
        logger.info(f"Analyzing results for task {task_id}")
        
        # Create a summary of current tasks
        current_tasks_summary = []
        for tid, task in state.task_manager.get("tasks", {}).items():
            current_tasks_summary.append({
                "id": tid,
                "name": task.get("name", ""),
                "description": task.get("description", ""),
                "tool": task.get("tool", ""),
                "status": task.get("status", "")
            })
        
        # Create scope summary
        scope_enforcer_dict = state.scope_enforcer
        scope_summary = "Domains: " + ", ".join(scope_enforcer_dict.get("domains", []) + 
                                               scope_enforcer_dict.get("wildcard_domains", []))
        scope_summary += "\nIP Ranges: " + ", ".join(str(ip) for ip in scope_enforcer_dict.get("ip_ranges", []))
        
        # Create the prompt
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity analyst."),
            HumanMessage(content=RESULT_ANALYSIS_PROMPT.format(
                task=task_dict,
                results=results,
                current_tasks=current_tasks_summary,
                scope=scope_summary
            ))
        ])
        
        # Parse the output as JSON
        chain = prompt | self.llm | JsonOutputParser()
        
        # Execute the chain
        try:
            new_tasks = chain.invoke({})
            
            # Add new tasks to the task manager
            if new_tasks and len(new_tasks) > 0:
                # Rebuild task manager from state if needed
                if hasattr(state, "task_manager") and isinstance(state.task_manager, dict):
                    self.task_manager.from_dict(state.task_manager)
                
                for task_data in new_tasks:
                    task = Task(
                        id=task_data.get("id", str(uuid.uuid4())),
                        name=task_data.get("name", ""),
                        description=task_data.get("description", ""),
                        tool=task_data.get("tool", ""),
                        arguments=task_data.get("arguments", {}),
                        dependencies=task_data.get("dependencies", [])
                    )
                    self.task_manager.add_task(task)
                
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
        
        # Collect all task results
        all_results = {}
        for task_id, result in state.results.items():
            task_dict = state.task_manager.get("tasks", {}).get(task_id, {})
            all_results[task_id] = {
                "task": task_dict,
                "result": result
            }
        
        # Create scope summary
        scope_enforcer_dict = state.scope_enforcer
        scope_summary = "Domains: " + ", ".join(scope_enforcer_dict.get("domains", []) + 
                                               scope_enforcer_dict.get("wildcard_domains", []))
        scope_summary += "\nIP Ranges: " + ", ".join(str(ip) for ip in scope_enforcer_dict.get("ip_ranges", []))
        
        # Create prompt for report generation
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity report writer."),
            HumanMessage(content=REPORT_GENERATION_PROMPT.format(
                objectives="\n".join(state.objectives),
                scope=scope_summary,
                tasks=state.task_manager.get("tasks", {}),
                results=all_results
            ))
        ])
        
        # Generate the report
        chain = prompt | self.llm
        
        try:
            report = chain.invoke({})
            state.report = {
                "content": report.content,
                "timestamp": self.task_manager.get_current_time(),
                "execution_summary": {
                    "total_tasks": len(state.task_manager.get("tasks", {})),
                    "completed_tasks": sum(1 for task in state.task_manager.get("tasks", {}).values() 
                                           if task.get("status") == TaskStatus.COMPLETED.value),
                    "failed_tasks": sum(1 for task in state.task_manager.get("tasks", {}).values() 
                                        if task.get("status") == TaskStatus.FAILED.value),
                    "skipped_tasks": sum(1 for task in state.task_manager.get("tasks", {}).values() 
                                         if task.get("status") == TaskStatus.SKIPPED.value)
                }
            }
            
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
            scope_enforcer={
                "domains": self.scope_enforcer.domains,
                "wildcard_domains": self.scope_enforcer.wildcard_domains,
                "ip_ranges": [str(ip) for ip in self.scope_enforcer.ip_ranges],
                "enabled": self.scope_enforcer.enabled
            }
        )
        
        # Run the workflow
        logger.info(f"Starting cybersecurity workflow with objectives: {objectives}")
        final_state = self.workflow.invoke(initial_state)
        
        return {
            "report": final_state.report,
            "results": final_state.results,
            "execution_log": final_state.execution_log,
            "error_log": final_state.error_log
        }
    
    def _setup_scope(self, scope_config: Dict[str, Any]) -> None:
        """
        Set up the scope enforcer from configuration.
        
        Args:
            scope_config: Configuration for the scope enforcer
        """
        # Reset the scope enforcer
        self.scope_enforcer = ScopeEnforcer()
        
        # Add domains
        for domain in scope_config.get("domains", []):
            self.scope_enforcer.add_domain(domain)
        
        # Add wildcard domains
        for wildcard in scope_config.get("wildcard_domains", []):
            self.scope_enforcer.add_wildcard_domain(wildcard)
        
        # Add IP ranges
        for ip_range in scope_config.get("ip_ranges", []):
            self.scope_enforcer.add_ip_range(ip_range)
        
        # Add individual IPs
        for ip in scope_config.get("ips", []):
            self.scope_enforcer.add_ip(ip)
        
        # Set enabled status
        self.scope_enforcer.enabled = scope_config.get("enabled", True)
        
        logger.info(f"Scope enforcer configured with {len(self.scope_enforcer.domains)} domains, "
                   f"{len(self.scope_enforcer.wildcard_domains)} wildcard domains, and "
                   f"{len(self.scope_enforcer.ip_ranges)} IP ranges")