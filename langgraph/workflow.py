import json
import logging
import uuid
from typing import Dict, List, Any, Tuple, Optional, Callable
from pydantic import BaseModel, Field

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI

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

For nmap tasks, provide parameters in this strict JSON format:
```json
{{"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}}
```

Each task must be a valid JSON object with these EXACT fields (all fields are REQUIRED):
- "id": unique string identifier (e.g., "task1", "recon-1")
- "name": short descriptive task name
- "description": detailed description
- "tool": tool to use (only "nmap" is available)
- "params": JSON object with tool-specific parameters (MUST include "target")
- "depends_on": array of task IDs this task depends on (can be empty array [])

Your ENTIRE response must be a valid JSON array of task objects, like this:

[
  {{
    "id": "task1",
    "name": "Initial ping sweep",
    "description": "Perform a ping sweep to identify live hosts",
    "tool": "nmap",
    "params": {{
      "target": "example.com",
      "scan_type": "ping"
    }},
    "depends_on": []
  }},
  {{
    "id": "task2",
    "name": "Port scan live hosts",
    "description": "Scan for open ports on live hosts",
    "tool": "nmap",
    "params": {{
      "target": "example.com",
      "scan_type": "syn",
      "ports": "1-1000"
    }},
    "depends_on": ["task1"]
  }}
]

IMPORTANT: 
1. Your response must begin with '[' and end with ']'
2. Each JSON object must be properly formatted with double quotes
3. No extra text or explanation before or after the JSON array
4. Commas between objects but NOT after the last object
5. All field names must be in double quotes
6. The "params" object MUST include "target"
7. Use complete domain names, not partial domains
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

I need your response in a specific format. You must return a valid JSON array of tasks, structured as shown below:

```json
[
  {{
    "id": "unique_id_string",
    "name": "Descriptive task name",
    "description": "Detailed description",
    "tool": "nmap",
    "params": {{"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}}
  }}
]
```

Important rules for your response:
1. Start your response with a valid JSON array, enclosed in square brackets []
2. Each task in the array must be a valid JSON object with all required fields
3. Do not include any explanation text before or after the JSON array
4. Always include the "target" parameter in the params object
5. Return an empty array [] if no new tasks are needed

Return just the JSON array. No extra text, just valid JSON.
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
    Extracts a JSON array from text, handling various formats and common LLM formatting issues.
    """
    logger.debug(f"Attempting to extract JSON array from: {text[:300]}...")
    
    # Try direct JSON loading first (fast path)
    try:
        json_obj = json.loads(text)
        if isinstance(json_obj, list):
            logger.debug("Successfully parsed JSON array directly")
            return json_obj
    except json.JSONDecodeError:
        pass  # Continue with more robust parsing

    # Use regex to find JSON-like structures
    # First, try to find a complete array [...] pattern
    array_pattern = re.compile(r'(\[[\s\S]*?\])', re.DOTALL)
    match = array_pattern.search(text)

    if match:
        json_array_str = match.group(1).strip()
        logger.debug(f"Found potential JSON array: {json_array_str[:100]}...")
        
        # Clean up common JSON issues
        cleaned_str = json_array_str
        
        # Remove trailing commas (common LLM error)
        cleaned_str = re.sub(r',\s*]', ']', cleaned_str)
        
        # Fix missing quotes around keys (another common error)
        # This regex finds identifiers followed by a colon that aren't in quotes
        cleaned_str = re.sub(r'(\s*)(\w+)(\s*):(\s*)', r'\1"\2"\3:\4', cleaned_str)
        
        # Fix single quotes used instead of double quotes
        cleaned_str = cleaned_str.replace("'", '"')
        
        # Fix unquoted True/False/None values
        cleaned_str = re.sub(r':\s*True', r': true', cleaned_str)
        cleaned_str = re.sub(r':\s*False', r': false', cleaned_str)
        cleaned_str = re.sub(r':\s*None', r': null', cleaned_str)
        
        try:
            json_array = json.loads(cleaned_str)
            if isinstance(json_array, list):
                logger.info(f"Successfully extracted JSON array with {len(json_array)} items after cleaning")
                return json_array
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON array after cleaning: {e}")
            logger.debug(f"Problematic JSON: {cleaned_str}")

    # If we're here, try a more aggressive approach - find each object separately
    logger.info("Attempting to extract individual JSON objects")
    object_pattern = re.compile(r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})', re.DOTALL)
    objects = object_pattern.findall(text)

    if objects:
        result = []
        for obj_str in objects:
            try:
                # Apply the same cleaning as above
                cleaned_obj = obj_str
                cleaned_obj = re.sub(r'(\s*)(\w+)(\s*):(\s*)', r'\1"\2"\3:\4', cleaned_obj)
                cleaned_obj = cleaned_obj.replace("'", '"')
                cleaned_obj = re.sub(r':\s*True', r': true', cleaned_obj)
                cleaned_obj = re.sub(r':\s*False', r': false', cleaned_obj)
                cleaned_obj = re.sub(r':\s*None', r': null', cleaned_obj)
                
                obj = json.loads(cleaned_obj)
                if isinstance(obj, dict):
                    result.append(obj)
            except json.JSONDecodeError:
                continue
        
        if result:
            logger.info(f"Recovered {len(result)} individual JSON objects")
            return result

    # Last resort: try to convert lines that look like YAML into JSON objects
    logger.info("Attempting YAML-like parsing as last resort")
    result = []

    # Split by what appears to be separate tasks (looking for patterns like "- id:" or "1. id:")
    task_pattern = re.compile(r'(?:^|\n)(?:[-*]|\d+\.)\s+', re.MULTILINE)
    tasks = task_pattern.split(text)

    for task_text in tasks:
        if not task_text.strip():
            continue
            
        obj = {}
        # Look for key-value pairs
        lines = task_text.strip().split('\n')
        current_key = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check if this line starts a new key
            kv_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:(.*?)$', line)
            if kv_match:
                current_key = kv_match.group(1)
                value = kv_match.group(2).strip()
                
                # Handle special values
                if value.lower() in ('true', 'yes'):
                    obj[current_key] = True
                elif value.lower() in ('false', 'no'):
                    obj[current_key] = False
                elif value.lower() in ('null', 'none', ''):
                    obj[current_key] = None
                # Try to parse as JSON if it looks like JSON
                elif value.startswith('{') or value.startswith('['):
                    try:
                        obj[current_key] = json.loads(value.replace("'", '"'))
                    except:
                        obj[current_key] = value
                # Just store as string
                else:
                    obj[current_key] = value
            elif current_key and line:
                # Continuation of previous value
                if isinstance(obj[current_key], str):
                    obj[current_key] += " " + line
        
        # Only add if we found at least some keys
        if obj:
            # Generate an ID if missing
            if "id" not in obj:
                obj["id"] = str(uuid.uuid4())
            result.append(obj)

    if result:
        logger.info(f"Created {len(result)} tasks using YAML-like parsing")
        return result

    # If we get here, we failed to extract anything useful
    logger.error("Failed to extract any JSON data from the text")
    raise ValueError("Could not extract valid JSON tasks from the response")

class CybersecurityWorkflow: 
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
        setattr(workflow, "recursion_limit", 100)

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

        # Create a default task in case everything else fails
        fallback_task = Task(
            id="fallback-scan",
            name="Emergency Fallback Scan",
            description="This is a fallback scan created when task decomposition failed",
            tool="nmap",
            params={"target": self.scope_validator.domains[0] if self.scope_validator.domains else "example.com", 
                    "scan_type": "ping"},
            depends_on=[]
        )

        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity task planning assistant who ONLY returns valid JSON arrays."),
            HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                objective="\n".join(state.objectives),
                scope=scope_str
            ))
        ])

        chain = prompt | self.llm

        try:
            raw_output = chain.invoke({})
            self.debug_llm_output(raw_output, "task_decomposition")
            
            if hasattr(raw_output, "content"):
                raw_output = raw_output.content

            logger.debug(f"Raw LLM output: {raw_output}")

            # Try to extract tasks using our improved extraction function
            tasks_list = extract_json_array(raw_output)
            
            if not tasks_list:
                logger.warning("No tasks were extracted from the LLM output")
                # Add fallback task
                self.task_manager.add_task(fallback_task)
                state.task_manager = self.task_manager.to_dict()
                return state

            # Limit to first 10 tasks if needed
            if len(tasks_list) > 10:
                logger.info(f"Limiting tasks: Only the first 10 of {len(tasks_list)} tasks will be processed")
                tasks_list = tasks_list[:10]

            tasks_added = 0
            for task_data in tasks_list:
                # Only process if task_data is a dict
                if not isinstance(task_data, dict):
                    logger.warning(f"Skipping invalid task data (expected dict, got {type(task_data)}): {task_data}")
                    continue
                    
                # Check for required fields
                required_fields = ["name", "tool", "params"]
                if not all(field in task_data for field in required_fields):
                    logger.warning(f"Skipping task missing required fields: {task_data}")
                    continue
                    
                # Verify the tool is valid
                if task_data.get("tool") != "nmap":
                    logger.warning(f"Skipping task with invalid tool: {task_data.get('tool')}")
                    continue
                    
                # Verify params contains target
                params = task_data.get("params", {})
                if not isinstance(params, dict) or "target" not in params:
                    logger.warning(f"Skipping task with invalid params (missing target): {params}")
                    continue
                    
                task_id = task_data.get("id")
                if not task_id:
                    task_id = str(uuid.uuid4())
                    
                # Create the task
                task = Task(
                    id=task_id,
                    name=task_data.get("name", ""),
                    tool=task_data.get("tool", ""),
                    params=params,
                    description=task_data.get("description", ""),
                    max_retries=task_data.get("max_retries", 3),
                    depends_on=task_data.get("depends_on", task_data.get("dependencies", []))
                )
                
                # Add it if the target is in scope
                target = params.get("target", "")
                if target and self.scope_validator.is_in_scope(target):
                    self.task_manager.add_task(task)
                    tasks_added += 1
                else:
                    logger.warning(f"Skipping task with out-of-scope target: {target}")

            # If we couldn't add any tasks, add the fallback task
            if tasks_added == 0:
                logger.warning("No valid tasks were created, adding fallback task")
                self.task_manager.add_task(fallback_task)
                
            state.task_manager = self.task_manager.to_dict()
            logger.info(f"Created {tasks_added} tasks from objectives")
        except Exception as e:
            logger.error(f"Error decomposing tasks: {str(e)}")
            state.error_log.append(f"Error decomposing tasks: {str(e)}")
            # Add fallback task
            self.task_manager.add_task(fallback_task)
            state.task_manager = self.task_manager.to_dict()
        
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

    # Add these modifications to the _execute_task method
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

            # OPTIMIZATION 1: Limit scan to 2 passes and increase efficiency
            if "scan_type" not in params or params["scan_type"] == "syn":
                # Add timing template to speed up scan (T4 is more aggressive but still reliable)
                if "arguments" in params:
                    params["arguments"] += " -T4 --max-retries=2"
                else:
                    params["arguments"] = "-T4 --max-retries=2"
            
            # Limit service detection to common ports if version detection is enabled
            if task.params.get("version_detection", False):
                if "arguments" in params:
                    params["arguments"] += " -sV --version-intensity=2"
                else:
                    params["arguments"] = "-sV --version-intensity=2"

            # Enforce reasonable timeout
            params["timeout"] = min(params.get("timeout", 180), 180)  # Cap at 3 minutes

            if "sudo" in params and isinstance(tool, NmapScanner):
                tool.sudo = params.pop("sudo")

            logger.info(f"Executing nmap scan with parameters: {params}")
            result = tool.scan(**params)
            self.debug_nmap_results(result, task.id)

            # OPTIMIZATION 2: Trim result data before storing
            if isinstance(result, dict):
                # Remove or truncate large fields
                if "stdout" in result:
                    result["stdout_summary"] = self._summarize_stdout(result.pop("stdout"))
                if "stderr" in result and len(result["stderr"]) > 1000:
                    result["stderr"] = result["stderr"][:1000] + "... [truncated]"
                
                # Process host data to make it more compact
                if "hosts" in result:
                    for host in result["hosts"]:
                        # Summarize port data
                        if "ports" in host:
                            host["ports_summary"] = self._summarize_ports(host["ports"])
                            # Keep only key port information
                            host["ports"] = [self._extract_key_port_info(p) for p in host["ports"]]

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

    # Add these helper methods for data optimization
    def _summarize_stdout(self, stdout_text):
        """Extract and summarize the most relevant parts of nmap stdout."""
        if not stdout_text:
            return ""
        
        # Extract only the most important sections
        important_lines = []
        
        lines = stdout_text.split('\n')
        for i, line in enumerate(lines):
            # Include scan report headers and port details
            if "Nmap scan report for" in line or "PORT" in line or "open" in line or "filtered" in line:
                important_lines.append(line)
            # Include lines with service information
            elif "/tcp" in line or "/udp" in line:
                important_lines.append(line)
        
        # If we have very few important lines, include more context
        if len(important_lines) < 5 and len(lines) > 5:
            return "\n".join(lines[:20])  # First 20 lines
        
        return "\n".join(important_lines)

    def _summarize_ports(self, ports):
        """Create a compact summary of ports."""
        if not ports:
            return "No ports found"
        
        open_ports = []
        filtered_ports = []
        closed_ports = []
        
        for port in ports:
            port_id = port.get('id', 'unknown')
            protocol = port.get('protocol', 'unknown')
            port_str = f"{port_id}/{protocol}"
            
            state = port.get('state', {}).get('state', 'unknown')
            if state == 'open':
                service = port.get('service', {}).get('name', '')
                if service:
                    port_str += f" ({service})"
                open_ports.append(port_str)
            elif state == 'filtered':
                filtered_ports.append(port_str)
            elif state == 'closed':
                closed_ports.append(port_str)
        
        summary = []
        if open_ports:
            summary.append(f"Open ports: {', '.join(open_ports)}")
        if filtered_ports:
            summary.append(f"Filtered ports: {', '.join(filtered_ports)}")
        if closed_ports:
            summary.append(f"Closed ports: {', '.join(closed_ports)}")
        
        return " | ".join(summary)

    def _extract_key_port_info(self, port):
        """Extract only the most essential information from port data."""
        # Start with a basic subset of port data
        essential_port = {
            'id': port.get('id'),
            'protocol': port.get('protocol'),
            'state': {'state': port.get('state', {}).get('state')}
        }
        
        # Include service info if available
        if 'service' in port:
            service = port['service']
            essential_port['service'] = {
                'name': service.get('name'),
                'product': service.get('product')
            }
            
            # Keep version and extrainfo if they exist
            if 'version' in service:
                essential_port['service']['version'] = service['version']
            if 'extrainfo' in service:
                essential_port['service']['extrainfo'] = service['extrainfo']
        
        return essential_port


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
        
        # OPTIMIZATION: Split analysis into smaller chunks if needed
        return self._analyze_results_with_chunking(state, task, results)

    def _analyze_results_with_chunking(self, state: AgentState, task: Task, results: Any) -> AgentState:
        """Analyze results using chunking for large result sets."""
        # Prepare a highly summarized version of the results
        results_summary = self._create_result_summary(results)
        
        # Get current tasks summary
        current_tasks_summary = []
        for t in self.task_manager.get_all_tasks():
            current_tasks_summary.append({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "tool": t.tool,
                "status": t.status.value
            })

        # Get scope information
        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        # STEP 1: Initial high-level analysis with summarized data
        high_level_prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content="You are a cybersecurity analyst reviewing scan results. Provide a concise analysis."),
            HumanMessage(content=f"""
    Analyze these scan results summary to identify key security findings:

    ORIGINAL TASK: {task.to_dict()}
    SCAN RESULTS SUMMARY: {results_summary}
    TARGET SCOPE: {scope_str}

    Respond with the 3-5 most important security observations in bullet points.
    """)
        ])

        try:
            # Get initial high-level analysis
            chain = high_level_prompt | self.llm
            high_level_analysis = chain.invoke({})
            high_level_text = high_level_analysis.content if hasattr(high_level_analysis, "content") else str(high_level_analysis)
            
            # STEP 2: Second pass to determine if follow-up tasks are needed
            followup_prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity analyst who responds ONLY with valid JSON."),
                HumanMessage(content=f"""
    Based on these scan findings, determine if any follow-up tasks are needed.

    ORIGINAL TASK: {task.to_dict()}
    HIGH-LEVEL FINDINGS: {high_level_text}
    CURRENT TASKS: {current_tasks_summary}
    TARGET SCOPE: {scope_str}

    IMPORTANT: Your ENTIRE response must be a valid JSON array, even if empty.

    If new tasks are needed, return JSON in this EXACT format:
    [
    {{
        "id": "unique_task_id",
        "name": "Short task name",
        "description": "Detailed description",
        "tool": "nmap", 
        "params": {{
        "target": "domain.com",
        "scan_type": "syn",
        "ports": "1-1000"
        }},
        "depends_on": []
    }}
    ]

    If no new tasks are needed, return EXACTLY:
    []

    Rules:
    1. Only tasks that use "nmap" as the tool
    2. Every task MUST have all fields shown above
    3. The "params" object MUST include "target"
    4. NO explanation text before or after the JSON
    5. Only suggest reasonable follow-up tasks based on the findings
    6. Ensure targets are within the specified scope
    """)
            ])

            # Get follow-up tasks recommendations
            chain = followup_prompt | self.llm
            followup_result = chain.invoke({})
            followup_text = followup_result.content if hasattr(followup_result, "content") else str(followup_result)
            
            # Combine analyses and attach to task result
            if task.result:
                if isinstance(task.result, dict):
                    task.result['analysis'] = {
                        'high_level': high_level_text,
                        'followup': followup_text
                    }
                else:
                    task.result = {
                        'original': task.result, 
                        'analysis': {
                            'high_level': high_level_text,
                            'followup': followup_text
                        }
                    }

            # Process follow-up tasks
            try:
                new_tasks = extract_json_array(followup_text)
                self._process_new_tasks(new_tasks, state)
            except Exception as e:
                logger.warning(f"Error processing follow-up tasks: {str(e)}")
                
        except Exception as e:
            error_msg = f"Error analyzing results: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)

        self.task_manager.update_task(task)
        state.task_manager = self.task_manager.to_dict()
        
        return state

    def _create_result_summary(self, results):
        """Create a concise summary of scan results."""
        summary = {}
        
        if not isinstance(results, dict):
            return f"Raw result: {str(results)[:500]}"
        
        # Include any summary fields already prepared
        if "stdout_summary" in results:
            summary["output"] = results["stdout_summary"]
        elif "stdout" in results:
            summary["output"] = results["stdout"][:500] + "..." if len(results["stdout"]) > 500 else results["stdout"]
        
        # Include host information if available
        if "hosts" in results:
            summary["hosts"] = []
            for host in results["hosts"]:
                host_summary = {
                    "ip": host.get("address", {}).get("addr", "unknown"),
                    "hostname": host.get("hostnames", [{"name": "unknown"}])[0].get("name", "unknown")
                }
                
                # Include port summaries if available
                if "ports_summary" in host:
                    host_summary["ports"] = host["ports_summary"]
                elif "ports" in host:
                    # Create a simple port summary if detailed one isn't available
                    open_ports = [f"{p.get('id')}/{p.get('protocol')} ({p.get('service', {}).get('name', 'unknown')})" 
                                for p in host.get("ports", []) 
                                if p.get("state", {}).get("state") == "open"]
                    if open_ports:
                        host_summary["ports"] = "Open ports: " + ", ".join(open_ports)
                
                summary["hosts"].append(host_summary)
        
        # Include scan statistics if available
        if "stats" in results:
            summary["stats"] = results["stats"]
        
        return summary

    def _process_new_tasks(self, new_tasks, state):
        """Process and add new tasks from analysis."""
        if not new_tasks or len(new_tasks) == 0:
            logger.info("No new tasks needed based on result analysis")
            return
            
        existing_count = len(self.task_manager.get_all_tasks())
        remaining_slots = max(0, 10 - existing_count)
        
        if remaining_slots <= 0:
            logger.info("Task limit reached (10 tasks). No new tasks will be added.")
            return
            
        logger.info(f"Adding up to {remaining_slots} new tasks from analysis")
        tasks_added = 0
        
        for task_data in new_tasks[:remaining_slots]:
            # Skip invalid task data
            if not isinstance(task_data, dict):
                continue
                
            # Check required fields
            required_fields = ["id", "name", "description", "tool", "params"]
            if not all(field in task_data for field in required_fields):
                continue
                
            # Skip tasks with invalid tool
            if task_data["tool"] != "nmap":
                continue
                
            # Skip tasks with invalid params
            params = task_data.get("params", {})
            if not isinstance(params, dict) or "target" not in params:
                continue
                
            # Get dependencies
            depends_on = task_data.get("depends_on", [])
            if not isinstance(depends_on, list):
                depends_on = []
                
            # Create task ID if needed
            task_id = task_data.get("id")
            if not task_id:
                task_id = str(uuid.uuid4())
                
            # Create and add the new task if target is in scope
            new_task = Task(
                id=task_id,
                name=task_data.get("name", ""),
                tool="nmap",
                params=params,
                description=task_data.get("description", ""),
                depends_on=depends_on
            )
            
            target = params.get("target", "")
            if target and self.scope_validator.is_in_scope(target):
                self.task_manager.add_task(new_task)
                tasks_added += 1
        
        logger.info(f"Added {tasks_added} new tasks based on analysis")
        state.task_manager = self.task_manager.to_dict()

    def _generate_report(self, state: AgentState) -> AgentState:
        """Generate the final security report using a multi-step approach."""
        logger.info("Generating final security report")

        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)

        # Get scope information
        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)

        # Initial placeholder report
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
            # STEP 1: Summarize key findings first
            findings_summary = self._summarize_key_findings(state)
            
            # STEP 2: Generate executive summary
            executive_summary = self._generate_executive_summary(state, findings_summary, scope_str)
            
            # STEP 3: Generate technical details and recommendations
            technical_details = self._generate_technical_details(state, findings_summary)
            
            # STEP 4: Combine into final report
            report_content = f"""# Security Assessment Report

    ## Executive Summary
    {executive_summary}

    ## Methodology
    The security assessment was conducted using automated scanning tools, specifically Nmap for port scanning and service detection. The scope included {scope_str}.

    ## Key Findings
    {findings_summary}

    ## Recommendations
    {technical_details.get('recommendations', 'No specific recommendations were identified.')}

    ## Technical Details
    {technical_details.get('details', 'No detailed technical information available.')}
    """

            state["report"] = {
                "content": report_content,
                "timestamp": self.task_manager.get_current_time().isoformat(),
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
            
            # Create a simplified fallback report
            fallback_report = self._generate_fallback_report(state, scope_str)
            state["report"] = fallback_report
            logger.info("Using fallback report due to error")

        return state

    def _summarize_key_findings(self, state):
        """Extract and summarize key findings from the results."""
        findings = []
        
        # Go through all completed tasks
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if not task or task.status != TaskStatus.COMPLETED:
                continue
                
            # Extract high-level analysis if available
            if isinstance(result, dict) and 'analysis' in result:
                analysis = result['analysis']
                if isinstance(analysis, dict) and 'high_level' in analysis:
                    findings.append(analysis['high_level'])
                elif isinstance(analysis, str):
                    findings.append(analysis)
                    
            # Extract port information if available
            if isinstance(result, dict) and 'hosts' in result:
                for host in result['hosts']:
                    if 'ports_summary' in host:
                        findings.append(f"Host {host.get('address', {}).get('addr', 'unknown')}: {host['ports_summary']}")
        
        if not findings:
            return "No significant findings were identified."
        
        return "\n\n".join(findings)

    def _generate_executive_summary(self, state, findings_summary, scope_str):
        """Generate the executive summary section."""
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity report writer. Generate a concise executive summary."),
                HumanMessage(content=f"""
    Write a brief executive summary (max 250 words) for a security assessment report.

    Scope: {scope_str}
    Objectives: {' '.join(state.objectives)}
    Key Findings: {findings_summary}

    Focus on high-level business impact and overall security posture.
    """)
            ])

            chain = prompt | self.llm
            summary = chain.invoke({})
            summary_text = summary.content if hasattr(summary, "content") else str(summary)
            return summary_text.strip()
        except Exception as e:
            logger.warning(f"Error generating executive summary: {str(e)}")
            return "This security assessment evaluated the specified targets. Several findings were identified that should be addressed according to their severity."

    def _generate_technical_details(self, state, findings_summary):
        """Generate technical details and recommendations."""
        try:
            # Extract technical information from results
            technical_info = []
            for task_id, result in state.results.items():
                task = self.task_manager.get_task(task_id)
                if not task or task.status != TaskStatus.COMPLETED:
                    continue
                    
                # Add basic task information
                task_info = f"### {task.name}\n\n"
                task_info += f"**Target:** {task.params.get('target', 'Unknown')}\n"
                task_info += f"**Tool:** {task.tool}\n\n"
                
                # Add key findings for this task
                if isinstance(result, dict):
                    if 'hosts' in result:
                        for host in result['hosts']:
                            ip = host.get('address', {}).get('addr', 'unknown')
                            hostname = host.get('hostnames', [{'name': 'unknown'}])[0].get('name', 'unknown')
                            
                            task_info += f"**Host:** {ip}"
                            if hostname != 'unknown':
                                task_info += f" ({hostname})\n"
                            else:
                                task_info += "\n"
                            
                            # Add port information
                            if 'ports' in host:
                                task_info += "**Open Ports:**\n\n"
                                for port in host['ports']:
                                    if port.get('state', {}).get('state') == 'open':
                                        port_id = port.get('id', 'unknown')
                                        protocol = port.get('protocol', 'unknown')
                                        service = port.get('service', {})
                                        service_name = service.get('name', 'unknown')
                                        product = service.get('product', '')
                                        version = service.get('version', '')
                                        
                                        port_detail = f"- {port_id}/{protocol}: {service_name}"
                                        if product:
                                            port_detail += f" ({product}"
                                            if version:
                                                port_detail += f" {version}"
                                            port_detail += ")"
                                        
                                        task_info += port_detail + "\n"
                
                technical_info.append(task_info)
            
            # Generate recommendations based on findings
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity consultant providing actionable recommendations."),
                HumanMessage(content=f"""
    Based on these security findings, provide 3-5 specific, actionable recommendations:

    {findings_summary}

    Format each recommendation as a bullet point with a brief explanation of its importance.
    """)
            ])

            chain = prompt | self.llm
            recommendations = chain.invoke({})
            recommendations_text = recommendations.content if hasattr(recommendations, "content") else str(recommendations)
            
            return {
                "details": "\n\n".join(technical_info),
                "recommendations": recommendations_text.strip()
            }
        except Exception as e:
            logger.warning(f"Error generating technical details: {str(e)}")
            return {
                "details": "Technical details could not be generated due to an error.",
                "recommendations": "Recommendations could not be generated due to an error."
            }

    def _generate_fallback_report(self, state, scope_str):
        """Generate a simplified fallback report when the main report generation fails."""
        # Collect basic findings
        findings = []
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if not task:
                continue
                
            task_result = f"### {task.name} ({task.status.value})\n"
            task_result += f"Target: {task.params.get('target', 'Unknown')}\n"
            
            if task.status == TaskStatus.COMPLETED and isinstance(result, dict):
                if 'hosts' in result:
                    for host in result['hosts']:
                        ip = host.get('address', {}).get('addr', 'unknown')
                        task_result += f"\nHost: {ip}\n"
                        
                        if 'ports_summary' in host:
                            task_result += f"{host['ports_summary']}\n"
            
            findings.append(task_result)
        
        content = f"""# Security Assessment Report

    ## Scope
    {scope_str}

    ## Summary
    This report contains basic findings from the security assessment. A detailed analysis could not be generated.

    ## Findings
    {("\n".join(findings)) if findings else "No findings available."}

    ## Execution Summary
    - Total Tasks: {len(self.task_manager.get_all_tasks())}
    - Completed: {len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED])}
    - Failed: {len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED])}
    - Skipped: {len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])}
    """

        return {
            "content": content,
            "timestamp": self.task_manager.get_current_time().isoformat(),
            "execution_summary": {
                "total_tasks": len(self.task_manager.get_all_tasks()),
                "completed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED]),
                "failed_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.FAILED]),
                "skipped_tasks": len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.SKIPPED])
            }
        }

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
            compiled_workflow.recursion_limit = 100

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

    def debug_llm_output(self, output, context=""):
        """
        Helper function to log LLM output for debugging purposes
        """
        # Create debug directory if it doesn't exist
        os.makedirs("debug", exist_ok=True)
        
        # Generate a timestamp and random ID for the debug file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        random_id = str(uuid.uuid4())[:8]
        filename = f"debug/llm_output_{context}_{timestamp}_{random_id}.txt"
        
        # Save the output to file
        with open(filename, "w") as f:
            output_str = output.content if hasattr(output, "content") else str(output)
            f.write(f"=== CONTEXT: {context} ===\n\n")
            f.write(output_str)
        
        logger.debug(f"Saved LLM output to {filename}")
        
        return output
