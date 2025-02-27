import json
import logging
import uuid
from typing import Dict, List, Any, Optional
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
from scan.gobuster_scan import GobusterScanner
from scan.ffuf_scan import FFUFScanner
from scan.sqlmap_scan import SQLMapScanner

# Import utility modules
from utils.task_manager import TaskManager, Task, TaskStatus
from utils.scope import ScopeValidator
from utils.logger import setup_logger

# Setup logger
logger = logging.getLogger(__name__)

# Helper function to truncate long text
def truncate_text(text: str, max_length: int = 500) -> str:
    if not isinstance(text, str):
        text = str(text)
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text

# (Existing prompt strings remain unchanged)
TASK_DECOMPOSITION_PROMPT = '''
You are an expert cybersecurity analyst. Break down the following high-level security objective into concrete tasks using the available security tools listed below.

OBJECTIVE: {objective}
TARGET SCOPE: {scope}

Available tools:
1. nmap - For network mapping and port scanning
2. gobuster - For directory and file enumeration
3. ffuf - For web fuzzing to discover hidden endpoints
4. sqlmap - For testing SQL injection vulnerabilities

Create tasks covering different aspects of the security assessment. For each tool, create at least one relevant task if applicable to the objective.

Each task should have:
- "name": A short descriptive name
- "description": A detailed explanation
- "tool": One of: "nmap", "gobuster", "ffuf", or "sqlmap"
- "params": Parameters specific to the tool, always including "target"
- "depends_on": List of task IDs this task depends on (can be empty)

Example tasks:
[
    {
        "name": "Initial port scan",
        "description": "Identify open ports and services on the target",
        "tool": "nmap",
        "params": {
            "target": "example.com",
            "scan_type": "syn",
            "ports": "1-1000"
        },
        "depends_on": []
    },
    {
        "name": "Directory enumeration",
        "description": "Find hidden directories on the web server",
        "tool": "gobuster",
        "params": {
            "target": "http://example.com",
            "wordlist": "common.txt"
        },
        "depends_on": []
    },
    {
        "name": "Web fuzzing for endpoints",
        "description": "Discover hidden endpoints and parameters on the web application",
        "tool": "ffuf",
        "params": {
            "target": "http://example.com/FUZZ",
            "wordlist": "common.txt",
            "extensions": "php,html,txt"
        },
        "depends_on": []
    },
    {
        "name": "SQL injection testing",
        "description": "Scan for SQL injection vulnerabilities in the web application",
        "tool": "sqlmap",
        "params": {
            "target": "http://example.com/page.php?id=1",
            "level": 3,
            "risk": 2
        },
        "depends_on": []
    }
]

IMPORTANT FORMATTING INSTRUCTIONS:
1. Your ENTIRE response must be ONLY a valid JSON array with no other text
2. Start with '[' and end with ']'
3. Do not include any explanation, markdown code blocks, or text outside the JSON array
4. Each object in the array must have exactly the fields shown in the examples
5. All field names must be in double quotes (e.g., "name", not name)
6. Do NOT include "id" fields - these will be generated automatically
7. Ensure all JSON syntax is correct (commas between objects, no trailing commas)
'''

RESULT_ANALYSIS_PROMPT = ''' You are an expert cybersecurity analyst. Review these scan results and determine follow-up actions.

    ORIGINAL TASK: {task} SCAN RESULTS: {results} CURRENT TASKS: {current_tasks} TARGET SCOPE: {scope}

    Determine if any new tasks should be added. Focus on:

    Investigating open ports and services
    Following up on potential vulnerabilities
    Confirming uncertain results
    I need your response in a specific format. You must return a valid JSON array of tasks, structured as shown below:

    [
    {
        "id": "unique_id_string",
        "name": "Descriptive task name",
        "description": "Detailed description",
        "tool": "nmap",
        "params": {"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}
    }
    ]
    Important rules for your response:

    Start your response with a valid JSON array, enclosed in square brackets []
    Each task in the array must be a valid JSON object with all required fields
    Do not include any explanation text before or after the JSON array
    Always include the "target" parameter in the params object
    Return an empty array [] if no new tasks are needed '''

REPORT_GENERATION_PROMPT = ''' Please generate a complete security report based on the following information:

    OBJECTIVES: {"\n".join(state.objectives)}

    TARGET SCOPE: {scope_str}

    EXECUTED TASKS: {len(self.task_manager.get_all_tasks())} tasks were executed, with {len([t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.COMPLETED])} completed successfully.

    KEY FINDINGS: {raw_results}

    Please structure the report with:

    Executive Summary
    Methodology
    Key Findings
    Recommendations
    Technical Details '''

def extract_json_array(text: str) -> List[Dict[str, Any]]: 
    """ Extracts a JSON array from text, handling various formats and common LLM formatting issues. """ 
    logger.debug(f"Attempting to extract JSON array from: {text[:300]}...")
    
    try:
        json_obj = json.loads(text)
        if isinstance(json_obj, list):
            logger.debug("Successfully parsed JSON array directly")
            return json_obj
    except json.JSONDecodeError:
        pass

    array_pattern = re.compile(r'(\[[\s\S]*?\])', re.DOTALL)
    match = array_pattern.search(text)

    if match:
        json_array_str = match.group(1).strip()
        logger.debug(f"Found potential JSON array: {json_array_str[:100]}...")
        cleaned_str = json_array_str
        cleaned_str = re.sub(r',\s*]', ']', cleaned_str)
        cleaned_str = re.sub(r'(\s*)(\w+)(\s*):(\s*)', r'\1"\2"\3:\4', cleaned_str)
        cleaned_str = cleaned_str.replace("'", '"')
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

    logger.info("Attempting to extract individual JSON objects")
    object_pattern = re.compile(r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})', re.DOTALL)
    objects = object_pattern.findall(text)

    if objects:
        result = []
        for obj_str in objects:
            try:
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

    logger.error("Failed to extract any JSON data from the text")
    raise ValueError("Could not extract valid JSON tasks from the response")

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

def get_llm(model="gemma2-9b-it", temperature=0): 
    return ChatGroq(model=model, temperature=temperature)

class CybersecurityWorkflow: 
    def __init__(self, llm=None):
        """Initialize the workflow with tools and LLM."""
        self.llm = llm or get_llm()
        self.task_manager = TaskManager()
        self.scope_validator = ScopeValidator()

        # Initialize security tools with integrated wrappers.
        self.tools = {
            "nmap": NmapScanner(),
            "gobuster": GobusterScanner(),
            "ffuf": FFUFScanner(),
            "sqlmap": SQLMapScanner()
        }

        # Create the workflow graph with an increased recursion limit.
        self.workflow = self._build_workflow()

    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow."""
        workflow = StateGraph(AgentState)
        workflow.add_node("decompose_tasks", self._decompose_tasks)
        workflow.add_node("select_next_task", self._select_next_task)
        workflow.add_node("check_scope", self._check_scope)
        workflow.add_node("execute_task", self._execute_task)
        workflow.add_node("analyze_results", self._analyze_results)
        workflow.add_node("generate_report", self._generate_report)

        workflow.add_edge(START, "decompose_tasks")
        workflow.add_edge("decompose_tasks", "select_next_task")
        workflow.add_conditional_edges(
            "select_next_task",
            self._has_next_task,
            {True: "check_scope", False: "generate_report"}
        )
        workflow.add_conditional_edges(
            "check_scope",
            self._check_scope_condition,
            {True: "execute_task", False: "select_next_task"}
        )
        workflow.add_edge("execute_task", "analyze_results")
        workflow.add_edge("analyze_results", "select_next_task")
        workflow.add_edge("generate_report", END)
        setattr(workflow, "recursion_limit", 10000)
        return workflow

    def _check_scope_condition(self, state: AgentState) -> bool:
        try:
            task_id = state.current_task_id
            if not task_id:
                return False

            if isinstance(state.task_manager, dict):
                self.task_manager.from_dict(state.task_manager)
            task = self.task_manager.get_task(task_id)
            if not task:
                return False
            return task.status != TaskStatus.SKIPPED
        except Exception as e:
            logger.error(f"Error in _check_scope_condition: {str(e)}")
            return False

    def _decompose_tasks(self, state: AgentState) -> AgentState:
        logger.info("Decomposing high-level objectives into tasks")
        self.task_manager = TaskManager()

        # Construct the scope string
        domains = self.scope_validator.domains + self.scope_validator.wildcard_domains
        ip_ranges = self.scope_validator.ip_ranges
        scope_str = f"Domains: {', '.join(domains)}\nIP Ranges: {', '.join(map(str, ip_ranges))}"

        # Use the first domain as fallback target
        fallback_target = self.scope_validator.domains[0] if self.scope_validator.domains else "example.com"
        # If fallback_target does not have a protocol, add one for web tasks
        web_target = fallback_target if fallback_target.startswith("http") else f"http://{fallback_target}"

        # Create fallback tasks for each tool
        fallback_tasks = []

        # Fallback task for nmap (port scanning)
        fallback_tasks.append(Task(
            id="fallback-scan-nmap",
            name="Basic Port Scan",
            description="Basic port scan created when task decomposition failed",
            tool="nmap",
            params={"target": fallback_target, "scan_type": "syn", "ports": "1-1000"},
            depends_on=[]
        ))

        # Fallback task for gobuster (directory enumeration)
        fallback_tasks.append(Task(
            id="fallback-scan-gobuster",
            name="Directory Enumeration",
            description="Basic directory enumeration created when task decomposition failed",
            tool="gobuster",
            params={"target": web_target, "wordlist": "common.txt"},
            depends_on=[]
        ))

        # Fallback task for ffuf (web fuzzing)
        fallback_tasks.append(Task(
            id="fallback-scan-ffuf",
            name="Web Fuzzing for Endpoints",
            description="Basic web fuzzing created when task decomposition failed",
            tool="ffuf",
            params={"target": f"{web_target}/FUZZ", "wordlist": "common.txt", "extensions": "php,html,txt"},
            depends_on=[]
        ))

        # Fallback task for sqlmap (SQL injection testing)
        fallback_tasks.append(Task(
            id="fallback-scan-sqlmap",
            name="SQL Injection Testing",
            description="Basic SQL injection testing created when task decomposition failed",
            tool="sqlmap",
            params={"target": f"{web_target}/page.php?id=1", "level": 3, "risk": 2},
            depends_on=[]
        ))

        def add_fallback(message: str):
            logger.warning(message)
            for task in fallback_tasks:
                if not self.task_manager.has_task(task.id):
                    self.task_manager.add_task(task)

        try:
            # Build prompt to generate tasks from high-level objectives
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=(
                    "You are a cybersecurity task planning assistant. "
                    "Return a VALID JSON array of tasks, no extra text. "
                    "Each task must have: name, description, tool, params, depends_on."
                )),
                HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                    objective="\n".join(state.objectives),
                    scope=scope_str
                ))
            ])

            chain = prompt | self.llm
            raw_output_obj = chain.invoke({})
            raw_output = getattr(raw_output_obj, "content", str(raw_output_obj)) or ""
            import re
            raw_output_clean = raw_output.strip()
            raw_output_clean = re.sub(r'^```(\w+)?', '', raw_output_clean)
            raw_output_clean = re.sub(r'```$', '', raw_output_clean)

            logger.debug(f"Raw LLM output after cleanup:\n{raw_output_clean}")

            try:
                tasks_list = extract_json_array(raw_output_clean)
            except Exception as json_error:
                logger.error(f"Failed to parse JSON from LLM output: {json_error}")
                logger.error(f"Raw output (truncated): {raw_output_clean[:500]}...")
                state.error_log.append(f"JSON parsing error: {json_error}")
                add_fallback("No tasks were extracted due to JSON error.")
                state.task_manager = self.task_manager.to_dict()
                return state

            if not tasks_list:
                add_fallback("No tasks were extracted from the LLM output.")
                state.task_manager = self.task_manager.to_dict()
                return state

            valid_tools = {"nmap", "gobuster", "ffuf", "sqlmap"}
            tasks_added = 0

            for task_data in tasks_list[:10]:  # limit to 10 tasks
                if not isinstance(task_data, dict):
                    logger.warning(f"Skipping invalid task data (not a dict): {task_data}")
                    continue

                missing_fields = [f for f in ("name", "description", "tool", "params") if f not in task_data]
                if missing_fields:
                    logger.warning(f"Skipping task missing fields {missing_fields}: {task_data}")
                    continue

                tool_name = task_data.get("tool")
                if tool_name not in valid_tools:
                    logger.warning(f"Skipping task with invalid tool: {tool_name}")
                    continue

                params = task_data.get("params", {})
                if not isinstance(params, dict) or "target" not in params:
                    logger.warning(f"Skipping task with invalid or missing 'target' in params: {params}")
                    continue

                # Generate a unique ID
                task_id = str(uuid.uuid4())
                new_task = Task(
                    id=task_id,
                    name=task_data["name"],
                    description=task_data["description"],
                    tool=tool_name,
                    params=params,
                    depends_on=task_data.get("depends_on", [])
                )

                target = params["target"]
                if self.scope_validator.is_in_scope(target):
                    self.task_manager.add_task(new_task)
                    tasks_added += 1
                else:
                    logger.warning(f"Skipping out-of-scope target: {target}")

            if tasks_added == 0:
                add_fallback("No valid tasks were added; using fallback tasks.")
            else:
                logger.info(f"Created {tasks_added} tasks from objectives.")

        except Exception as e:
            logger.error(f"Error decomposing tasks: {e}")
            state.error_log.append(f"Error decomposing tasks: {e}")
            add_fallback("Exception occurred during task decomposition; fallback tasks added.")

        state.task_manager = self.task_manager.to_dict()
        return state



    def _get_next_executable_task(self) -> Optional[Task]:
        try:
            for task in self.task_manager.get_all_tasks():
                if task.status == TaskStatus.PENDING:
                    deps_satisfied = all(
                        self.task_manager.get_task(dep_id) and 
                        self.task_manager.get_task(dep_id).status == TaskStatus.COMPLETED 
                        for dep_id in task.depends_on
                    )
                    if deps_satisfied:
                        return task
            return None
        except Exception as e:
            logger.error(f"Error getting next executable task: {str(e)}")
            return None

    def _select_next_task(self, state: AgentState) -> AgentState:
        logger.info("Selecting next task to execute")
        try:
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
        except Exception as e:
            logger.error(f"Error selecting next task: {str(e)}")
            state.error_log.append(f"Error selecting next task: {str(e)}")
            state.current_task_id = None
        return state

    def _execute_task(self, state: AgentState) -> AgentState:
        task_id = state.current_task_id
        if not task_id:
            logger.info("No task ID provided, skipping execution")
            return state

        task = None
        try:
            if isinstance(state.task_manager, dict):
                self.task_manager.from_dict(state.task_manager)
            
            task = self.task_manager.get_task(task_id)
            if not task:
                logger.warning(f"Task {task_id} not found, skipping execution")
                return state
            
            # Initialize task properties
            task.status = TaskStatus.RUNNING
            task.started_at = self.task_manager.get_current_time()
            if not hasattr(task, 'errors'):
                task.errors = []
            self.task_manager.update_task(task)
            
            logger.info(f"Executing task: {task.name} (ID: {task.id}) with tool: {task.tool}")
            
            # Get tool and validate parameters
            tool = self.tools.get(task.tool)
            if not tool:
                raise ValueError(f"Tool '{task.tool}' not found")
            
            params = task.params.copy()
            
            # Ensure a target is provided.
            if not params.get("target") and not params.get("target_url"):
                logger.error("Target parameter is missing.")
                raise ValueError("Target parameter is missing.")
            
            # Handle comma-separated targets
            if "target" in params and isinstance(params["target"], str) and "," in params["target"]:
                params["target"] = [t.strip() for t in params["target"].split(",")]
            
            # For gobuster, validate and ensure the wordlist exists
            if task.tool == "gobuster" and "wordlist" in params:
                # List of common wordlist paths to try if the specified one doesn't exist
                wordlist_paths = [
                    params["wordlist"],  # First try the user-specified wordlist
                    "/usr/share/wordlists/gobuster/common.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
                    "/usr/share/dirb/wordlists/common.txt"
                ]
                
                # Find the first wordlist that exists
                wordlist_found = False
                for wordlist in wordlist_paths:
                    if os.path.exists(wordlist):
                        if wordlist != params["wordlist"]:
                            logger.warning(f"Wordlist {params['wordlist']} not found, using {wordlist} instead")
                        params["wordlist"] = wordlist
                        wordlist_found = True
                        break
                
                if not wordlist_found:
                    raise ValueError(f"No valid wordlist found. Tried: {', '.join(wordlist_paths)}")
                    
                # Handle http_method parameter 
                if "http_method" in params:
                    method = params.pop("http_method")
                    if "extra_args" in params:
                        params["extra_args"] += f" -m {method}"
                    else:
                        params["extra_args"] = f"-m {method}"
            
            # For sqlmap, handle specific parameter transformations
            if task.tool == "sqlmap":
                # Map 'target' to 'target_url'
                if "target" in params:
                    params["target_url"] = params.pop("target")
                
                # Ensure URL has protocol
                if "target_url" in params and not params["target_url"].startswith(('http://', 'https://')):
                    params["target_url"] = f"http://{params['target_url']}"
                
                # Start with a simple scan first
                extra_args = params.get("extra_args", "")
                
                # For initial execution, simplify the command to improve success chance
                # Remove --dump-all and increase the timeout for the initial attempt
                if getattr(task, 'retry_count', 0) == 0:
                    # Don't use dump-all on first attempt
                    if "--dump-all" in extra_args:
                        extra_args = extra_args.replace("--dump-all", "")
                    params["extra_args"] = extra_args
                    
                    # Set a higher timeout for the first attempt
                    params["timeout"] = params.get("timeout", 300) + 120
                    
                    # On first attempt, just use --dbs to check for vulnerabilities without dumping
                    if "dump-all" in params:
                        del params["dump-all"]
                    
                    # Always include dbs flag for checking basic injection
                    params["dbs"] = True
                    
                    logger.info("First sqlmap attempt: using simplified parameters to improve success chance")
                else:
                    # For retry attempts, increase verbosity to debug issues
                    params["verbose"] = 3
                    
                # Properly handle SQLMap flag options
                sqlmap_flags = ["dbs", "batch", "forms", "tables", "columns", "current-user", "current-db"]
                for flag in sqlmap_flags:
                    if flag in params:
                        # If the parameter value is 'all' or True, set it to True to be treated as a flag
                        if params[flag] == 'all' or params[flag] is True:
                            params[flag] = True
            
           # For nmap, process tool-specific parameters
            if task.tool == "nmap":
                # Limit the ports range to 9000 if needed.
                if "ports" in params:
                    port_range = params["ports"]
                    try:
                        parts = port_range.split("-")
                        if len(parts) == 2:
                            start = int(parts[0])
                            end = int(parts[1])
                            if end > 9000:
                                logger.info(f"Restricting port range from {port_range} to {start}-9000")
                                params["ports"] = f"{start}-9000"
                    except Exception as e:
                        logger.warning(f"Failed to parse ports range '{port_range}': {e}")

                # Map 'script_args' to 'arguments' if present
                if "script_args" in params:
                    params["arguments"] = params.pop("script_args")
                
                # Handle script parameter - fix for ssh-vuln script not found error
                if "script" in params:
                    script_value = params.pop("script")
                    # Convert both 'ssh-vuln' and 'ssh-enum' to 'ssh-*'
                    if script_value in ["ssh-vuln", "ssh-enum"]:
                        script_value = "ssh-*"
                        logger.info("Converting '{}' to 'ssh-*' to run all SSH-related scripts".format(script_value))
                    if "arguments" in params:
                        params["arguments"] += f" --script={script_value}"
                    else:
                        params["arguments"] = f"--script={script_value}"
                
                # Handle scan type parameter
                if "scan_type" in params:
                    # Special case for SSH vulnerability scanning
                    if params["scan_type"] in ["ssh_vuln", "ssh_vulnerability"]:
                        params["scan_type"] = "ssh_vulnerability"
                        logger.info("Using predefined 'ssh_vulnerability' scan type")
                    elif params["scan_type"] == "syn":
                        if "arguments" in params:
                            params["arguments"] += " -T4 --max-retries=2"
                        else:
                            params["arguments"] = "-T4 --max-retries=2"
                else:
                    # Default scan behavior
                    if "arguments" in params:
                        params["arguments"] += " -T4 --max-retries=2"
                    else:
                        params["arguments"] = "-T4 --max-retries=2"
                
                # Add version detection if requested
                if task.params.get("version_detection", False):
                    if "arguments" in params:
                        params["arguments"] += " -sV --version-intensity=2"
                    else:
                        params["arguments"] = "-sV --version-intensity=2"

            
            # Set timeout and sudo if applicable
            params["timeout"] = min(params.get("timeout", 180), 300)  # Increase max timeout to 5 minutes
            if "sudo" in params and hasattr(tool, "sudo"):
                tool.sudo = params.pop("sudo")
            
            # Execute the scan
            logger.info(f"Executing {task.tool} scan with parameters: {params}")
            result = tool.scan(**params)
            
            # Save result and mark task as completed
            task.result = result
            task.status = TaskStatus.COMPLETED
            state.results[task.id] = result
            logger.info(f"Task {task.id} completed successfully")
            
        except Exception as e:
            error_msg = f"Error executing task {task_id} ({task.name if task else 'unknown'}): {str(e)}"
            logger.error(error_msg)
            if task:
                task.status = TaskStatus.FAILED
                task.errors.append(error_msg)
                task.retry_count = getattr(task, 'retry_count', 0) + 1
                if task.retry_count < getattr(task, 'max_retries', 3):
                    task.status = TaskStatus.RETRYING
                    retry_delay = min(2 ** task.retry_count, 60)
                    logger.info(f"Retrying task {task.id} ({task.name}) in {retry_delay}s, attempt {task.retry_count}")
                    
                    # For retry attempts with SQLMap, try a more conservative approach
                    if task.tool == "sqlmap" and task.retry_count == 1:
                        # Set a very basic scan for the retry
                        task.params["risk"] = "1"  # Lower risk level
                        task.params["level"] = "1"  # Lower detection level
                        task.params.pop("dump-all", None)  # Remove dump-all
                        logger.info("Adjusting SQLMap parameters for retry to use more conservative settings")
            state.error_log.append(error_msg)
            
        finally:
            if task:
                self.task_manager.update_task(task)
                state.task_manager = self.task_manager.to_dict()
                        
        return state

    def debug_scan_results(self, result: Any, task_id: str, tool_name: str) -> Any:
        try:
            os.makedirs("debug", exist_ok=True)
            with open(f"debug/{tool_name}_result_{task_id}.json", "w") as f:
                try:
                    json.dump(result, f, indent=2)
                except TypeError:
                    f.write(str(result))
            
            # Log scan output for debugging
            if isinstance(result, dict):
                if "stdout" in result:
                    logger.info(f"{tool_name} stdout: {result['stdout'][:500]}...")
                logger.info(f"Result keys: {list(result.keys())}")
                if "hosts" in result:
                    for host in result["hosts"]:
                        if "ports" in host:
                            logger.info(f"Found {len(host['ports'])} ports for host")
                            for port in host["ports"][:3]:  # Log only first 3 ports to avoid excessive logging
                                logger.info(f"Port details: {port}")
            return result
        except Exception as e:
            logger.error(f"Error in debug_scan_results: {str(e)}")
            return result

    def _summarize_stdout(self, stdout_text):
        if not stdout_text:
            return ""
        try:
            important_lines = []
            lines = stdout_text.split('\n')
            for i, line in enumerate(lines):
                if "Nmap scan report for" in line or "PORT" in line or "open" in line or "filtered" in line:
                    important_lines.append(line)
                elif "/tcp" in line or "/udp" in line:
                    important_lines.append(line)
            if len(important_lines) < 5 and len(lines) > 5:
                return "\n".join(lines[:20])
            return "\n".join(important_lines)
        except Exception as e:
            logger.error(f"Error summarizing stdout: {str(e)}")
            return stdout_text[:1000] + "... [truncated due to error]"

    def _summarize_ports(self, ports):
        if not ports:
            return "No ports found"
        try:
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
        except Exception as e:
            logger.error(f"Error summarizing ports: {str(e)}")
            return "Error summarizing port information"

    def _extract_key_port_info(self, port):
        try:
            essential_port = {
                'id': port.get('id'),
                'protocol': port.get('protocol'),
                'state': {'state': port.get('state', {}).get('state')}
            }
            if 'service' in port:
                service = port['service']
                essential_port['service'] = {
                    'name': service.get('name'),
                    'product': service.get('product')
                }
                if 'version' in service:
                    essential_port['service']['version'] = service['version']
                if 'extrainfo' in service:
                    essential_port['service']['extrainfo'] = service['extrainfo']
            return essential_port
        except Exception as e:
            logger.error(f"Error extracting port info: {str(e)}")
            return {'error': str(e)}

    def _has_next_task(self, state: AgentState) -> bool:
        try:
            if isinstance(state.task_manager, dict):
                self.task_manager.from_dict(state.task_manager)
            pending_tasks = [t for t in self.task_manager.get_all_tasks() if t.status == TaskStatus.PENDING]
            has_next = len(pending_tasks) > 0
            logger.info(f"Has next task check: {has_next} (found {len(pending_tasks)} pending tasks)")
            return has_next
        except Exception as e:
            logger.error(f"Error in has_next_task: {str(e)}")
            return False

    def _check_scope(self, state: AgentState) -> AgentState:
        try:
            task_id = state.current_task_id
            if not task_id:
                return state
                
            if isinstance(state.task_manager, dict):
                self.task_manager.from_dict(state.task_manager)
                
            task = self.task_manager.get_task(task_id)
            if not task:
                return state
                
            target = None
            if task.tool in ["nmap", "gobuster", "ffuf", "sqlmap"]:
                # For all tools, assume 'target' or 'target_url' key is used
                target = task.params.get("target") or task.params.get("target_url")
                
            if target:
                # Handle both string and list targets
                targets_to_check = [target] if isinstance(target, str) else target
                
                for t in targets_to_check:
                    is_in_scope = self.scope_validator.is_in_scope(t)
                    if not is_in_scope:
                        logger.warning(f"Task {task.id} ({task.name}) target {t} is out of scope - skipping")
                        task.status = TaskStatus.SKIPPED
                        if not hasattr(task, 'errors'):
                            task.errors = []
                        task.errors.append(f"Target {t} is out of scope")
                        self.task_manager.update_task(task)
                        
                        violation_log = {
                            "timestamp": self.task_manager.get_current_time().isoformat(),
                            "task_id": task.id,
                            "task_name": task.name,
                            "target": t,
                            "type": "scope_violation",
                            "message": "Target is out of scope"
                        }
                        state.execution_log.append(violation_log)
                        break  # Skip the task if any target is out of scope
                        
            state.task_manager = self.task_manager.to_dict()
        except Exception as e:
            logger.error(f"Error in check_scope: {str(e)}")
            state.error_log.append(f"Scope check error: {str(e)}")
            
        return state

    def _analyze_results(self, state: AgentState) -> AgentState:
        try:
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
                state.results[task_id] = {
                    "status": "no_results", 
                    "timestamp": self.task_manager.get_current_time().isoformat()
                }
                return state
                
            logger.info(f"Analyzing results for task {task_id}")
            return self._analyze_results_with_chunking(state, task, results)
        except Exception as e:
            logger.error(f"Error in analyze_results: {str(e)}")
            state.error_log.append(f"Results analysis error: {str(e)}")
            return state

    def _analyze_results_with_chunking(self, state: AgentState, task: Task, results: Any) -> AgentState:
        try:
            # Create summaries for analysis and truncate if too long
            results_summary = self._create_result_summary(results)
            results_summary = truncate_text(str(results_summary), 500)
            
            # Create a concise summary of current tasks (using a simple count)
            total_tasks = len(self.task_manager.get_all_tasks())
            current_tasks_summary = f"Total tasks: {total_tasks}"
            
            # Build and truncate the scope string
            scope_str = "Domains: " + ", ".join(
                self.scope_validator.domains + self.scope_validator.wildcard_domains
            )
            scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)
            scope_str = truncate_text(scope_str, 300)
            
            # Create a shortened version of the original task details
            task_summary = {
                "name": task.name,
                "tool": task.tool,
                "params": task.params
            }
            task_summary_str = truncate_text(str(task_summary), 300)
            
            # High-level analysis prompt with truncated information
            high_level_prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity analyst reviewing scan results. Provide a concise analysis."),
                HumanMessage(content=f"""
                    Analyze these scan results summary to identify key security findings:

                    ORIGINAL TASK: {task_summary_str}
                    SCAN RESULTS SUMMARY: {results_summary}
                    TARGET SCOPE: {scope_str}

                    Respond with the 3-5 most important security observations in bullet points.
                """)
            ])
            chain = high_level_prompt | self.llm
            high_level_analysis = chain.invoke({})
            high_level_text = high_level_analysis.content if hasattr(high_level_analysis, "content") else str(high_level_analysis)
            high_level_text = truncate_text(high_level_text, 300)
            
            # Followup tasks prompt with truncated details
            followup_prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity analyst who responds ONLY with valid JSON."),
                HumanMessage(content=f"""
                    Based on these scan findings, determine if any follow-up tasks are needed.

                    ORIGINAL TASK: {task_summary_str}
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
                        "params": {{"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}}
                    }}
                    ]

                    If no new tasks are needed, return EXACTLY:
                    []

                    Rules:
                    1. Only tasks that use one of the following tools: "nmap", "gobuster", "ffuf", or "sqlmap"
                    2. Every task MUST have all fields shown above
                    3. The "params" object MUST include "target"
                    4. NO explanation text before or after the JSON
                    5. Only suggest reasonable follow-up tasks based on the findings
                    6. Ensure targets are within the specified scope
                """)
            ])
            chain = followup_prompt | self.llm
            followup_result = chain.invoke({})
            followup_text = followup_result.content if hasattr(followup_result, "content") else str(followup_result)
            followup_text = truncate_text(followup_text, 500)
            
            # Store analysis in task result
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
            
            # Parse and process new tasks
            try:
                new_tasks = extract_json_array(followup_text)
                self._process_new_tasks(new_tasks, state)
            except Exception as e:
                logger.warning(f"Error processing follow-up tasks: {str(e)}")
                state.error_log.append(f"Follow-up task error: {str(e)}")
        except Exception as e:
            error_msg = f"Error analyzing results: {str(e)}"
            logger.error(error_msg)
            state.error_log.append(error_msg)
        
        # Update task and state
        self.task_manager.update_task(task)
        state.task_manager = self.task_manager.to_dict()
        return state

    def _create_result_summary(self, results):
        try:
            summary = {}
            if not isinstance(results, dict):
                return f"Raw result: {str(results)[:500]}"
                
            if "stdout_summary" in results:
                summary["output"] = results["stdout_summary"]
            elif "stdout" in results:
                summary["output"] = results["stdout"][:500] + "..." if len(results["stdout"]) > 500 else results["stdout"]
                
            if "hosts" in results:
                summary["hosts"] = []
                for host in results["hosts"]:
                    host_summary = {
                        "ip": host.get("address", {}).get("addr", "unknown"),
                        "hostname": host.get("hostnames", [{"name": "unknown"}])[0].get("name", "unknown")
                    }
                    if "ports_summary" in host:
                        host_summary["ports"] = host["ports_summary"]
                    elif "ports" in host:
                        open_ports = [
                            f"{p.get('id')}/{p.get('protocol')} ({p.get('service', {}).get('name', 'unknown')})" 
                            for p in host.get("ports", []) 
                            if p.get("state", {}).get("state") == "open"
                        ]
                        if open_ports:
                            host_summary["ports"] = "Open ports: " + ", ".join(open_ports)
                    summary["hosts"].append(host_summary)
                    
            if "stats" in results:
                summary["stats"] = results["stats"]
                
            return summary
        except Exception as e:
            logger.error(f"Error creating result summary: {str(e)}")
            return {"error": f"Failed to summarize results: {str(e)}"}

    def _process_new_tasks(self, new_tasks, state):
        if not new_tasks or len(new_tasks) == 0:
            logger.info("No new tasks needed based on result analysis")
            return
        existing_tasks = self.task_manager.get_all_tasks()
        remaining_slots = max(0, 10 - len(existing_tasks))
        if remaining_slots <= 0:
            logger.info("Task limit reached (10 tasks). No new tasks will be added.")
            return
        logger.info(f"Adding up to {remaining_slots} new tasks from analysis")
        tasks_added = 0
        for task_data in new_tasks[:remaining_slots]:
            if not isinstance(task_data, dict):
                continue
            required_fields = ["name", "description", "tool", "params"]
            if not all(field in task_data for field in required_fields):
                continue
            if task_data["tool"] not in ["nmap", "gobuster", "ffuf", "sqlmap"]:
                continue
            params = task_data.get("params", {})
            if not isinstance(params, dict) or "target" not in params:
                continue
            # Check for duplicates: if a task with the same name, tool, and target already exists, skip it
            duplicate = any(
                t.name == task_data["name"] and 
                t.tool == task_data["tool"] and 
                t.params.get("target") == params.get("target")
                for t in existing_tasks
            )
            if duplicate:
                continue
            # Always generate a new unique ID regardless of any provided ID
            task_id = str(uuid.uuid4())
            new_task = Task(
                id=task_id,
                name=task_data.get("name", ""),
                tool=task_data.get("tool", "nmap"),
                params=params,
                description=task_data.get("description", ""),
                depends_on=task_data.get("depends_on", [])
            )
            target = params.get("target", "")
            if target and self.scope_validator.is_in_scope(target):
                self.task_manager.add_task(new_task)
                tasks_added += 1
        logger.info(f"Added {tasks_added} new tasks based on analysis")
        state.task_manager = self.task_manager.to_dict()


    def _generate_report(self, state: AgentState) -> AgentState:
        logger.info("Generating final security report")
        if isinstance(state.task_manager, dict):
            self.task_manager.from_dict(state.task_manager)
        scope_str = "Domains: " + ", ".join(
            self.scope_validator.domains + self.scope_validator.wildcard_domains
        )
        scope_str += "\nIP Ranges: " + ", ".join(str(ip_range) for ip_range in self.scope_validator.ip_ranges)
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
            findings_summary = self._summarize_key_findings(state)
            executive_summary = self._generate_executive_summary(state, findings_summary, scope_str)
            technical_details = self._generate_technical_details(state, findings_summary)
            report_content = f"""# Security Assessment Report

        ## Executive Summary
        {executive_summary}

        ## Methodology
        The security assessment was conducted using automated scanning tools, including Nmap, Gobuster, ffuf, and sqlmap. The scope included {scope_str}.

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
            fallback_report = self._generate_fallback_report(state, scope_str)
            state["report"] = fallback_report
            logger.info("Using fallback report due to error")
        return state

    def _summarize_key_findings(self, state):
        findings = []
        for task_id, result in state.results.items():
            task = self.task_manager.get_task(task_id)
            if not task or task.status != TaskStatus.COMPLETED:
                continue
            if isinstance(result, dict) and 'analysis' in result:
                analysis = result['analysis']
                if isinstance(analysis, dict) and 'high_level' in analysis:
                    findings.append(analysis['high_level'])
                elif isinstance(analysis, str):
                    findings.append(analysis)
            if isinstance(result, dict) and 'hosts' in result:
                for host in result['hosts']:
                    if 'ports_summary' in host:
                        findings.append(f"Host {host.get('address', {}).get('addr', 'unknown')}: {host['ports_summary']}")
        if not findings:
            return "No significant findings were identified."
        return "\n\n".join(findings)

    def _generate_executive_summary(self, state, findings_summary, scope_str):
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
        try:
            technical_info = []
            for task_id, result in state.results.items():
                task = self.task_manager.get_task(task_id)
                if not task or task.status != TaskStatus.COMPLETED:
                    continue
                task_info = f"### {task.name}\n\n"
                task_info += f"**Target:** {task.params.get('target', 'Unknown')}\n"
                task_info += f"**Tool:** {task.tool}\n\n"
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
            compiled_workflow.recursion_limit = 10000
            final_state = compiled_workflow.invoke(initial_state, config={"recursion_limit": 50})

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
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    def debug_llm_output(self, output, context=""):
        os.makedirs("debug", exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        random_id = str(uuid.uuid4())[:8]
        filename = f"debug/llm_output_{context}_{timestamp}_{random_id}.txt"
        with open(filename, "w") as f:
            output_str = output.content if hasattr(output, "content") else str(output)
            f.write(f"=== CONTEXT: {context} ===\n\n")
            f.write(output_str)
        logger.debug(f"Saved LLM output to {filename}")
        return output