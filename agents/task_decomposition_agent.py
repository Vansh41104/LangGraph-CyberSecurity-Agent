from typing import Dict, Any, List
import re
import json
import uuid
import logging

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage

from agents.base_agent import BaseAgent
from utils.task_manager import Task, TaskStatus

logger = logging.getLogger(__name__)


TASK_DECOMPOSITION_PROMPT = '''
You are an expert cybersecurity analyst. Based on the following high-level security objective provided by the user, create the concrete tasks using the available security tools listed below. Only include tasks that are explicitly mentioned or clearly implied in the objective. If no specific tool is mentioned, choose the most appropriate tool for the task.

OBJECTIVE: {objective}
TARGET SCOPE: {scope}

Available tools:
1. nmap - For network mapping and port scanning
2. gobuster - For directory and file enumeration
3. ffuf - For web fuzzing to discover hidden endpoints
4. sqlmap - For testing SQL injection vulnerabilities

TASK EXTRACTION INSTRUCTIONS:
1. If TARGET SCOPE is empty or unspecified, extract ALL domains, IP addresses, and URLs from the OBJECTIVE.
2. Recognize and properly handle both domain names (e.g., example.com) and IP addresses (e.g., 192.168.1.1).
3. Only create tasks that are explicitly mentioned or clearly implied in the objective.
4. For each tool, create a task ONLY if it is explicitly specified or clearly required based on the objective.
5. If a tool is not explicitly mentioned, infer the most relevant tool based on the context of the objective.
6. Focus on the specific security assessment mentioned in the objective rather than creating a generic set of tasks.
7. For IP addresses, prioritize nmap for initial reconnaissance before using other tools.
8. For web domains, ensure proper protocol prefixes (http:// or https://) are included in targets when required.

Each task should have:
- "name": A short descriptive name
- "description": A detailed explanation
- "tool": One of: "nmap", "gobuster", "ffuf", or "sqlmap"
- "params": Parameters specific to the tool, always including "target" (can be domain name, IP address, or URL)
- "depends_on": List of task IDs this task depends on (can be empty)

IMPORTANT FORMATTING INSTRUCTIONS:
1. Your ENTIRE response must be ONLY a valid JSON array with no extra text.
2. Output raw JSON without any markdown formatting or triple backticks.
3. Start with '[' and end with ']'.
4. Do not include any explanation text.
'''


def extract_json_array(text: str) -> List[Dict[str, Any]]:
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


class TaskDecompositionAgent(BaseAgent):
    
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("Decomposing high-level objectives into tasks")
        
        objectives = state.get("objectives", [])
        if not objectives:
            logger.warning("No objectives provided for task decomposition")
            return state
        
        if self.task_manager.get_all_tasks():
            logger.info("Tasks already exist; skipping task decomposition.")
            return state
        
        self._extract_targets_from_objectives(objectives)
        
        fallback_target = self._get_fallback_target()
        
        scope_str = self.get_scope_string()
        
        try:
            tasks_list = self._generate_tasks_from_llm(objectives, scope_str)
            
            if not tasks_list:
                logger.error("No tasks were extracted from the LLM output.")
                state.setdefault("error_log", []).append("No tasks were extracted from the LLM output.")
                return state
            
            tasks_added = self._process_and_add_tasks(tasks_list, fallback_target, state)
            
            if tasks_added == 0:
                logger.error("No valid tasks were added from the provided prompt.")
            else:
                logger.info(f"Created {tasks_added} tasks from objectives.")
                
        except Exception as e:
            logger.error(f"Error decomposing tasks: {e}")
            state.setdefault("error_log", []).append(f"Error decomposing tasks: {e}")
        
        return state
    
    def _extract_targets_from_objectives(self, objectives: List[str]):
        if not self.scope_validator.domains and not self.scope_validator.wildcard_domains:
            domain_pattern = r'(https?://)?(?:www\.)?([\w.-]+\.[a-zA-Z]{2,})'
            for obj in objectives:
                for match in re.finditer(domain_pattern, obj):
                    extracted_domain = match.group(2)
                    self.scope_validator.add_domain(extracted_domain)
                    logger.info(f"Extracted domain {extracted_domain} from objective.")
        
        if not getattr(self.scope_validator, 'ips', []):
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for obj in objectives:
                for match in re.finditer(ip_pattern, obj):
                    ip_address = match.group()
                    self.scope_validator.add_ip(ip_address)
                    logger.info(f"Extracted IP address {ip_address} from objective.")
    
    def _get_fallback_target(self) -> str:
        if self.scope_validator.domains:
            return self.scope_validator.domains[0]
        elif getattr(self.scope_validator, 'ips', []):
            return self.scope_validator.ips[0]
        else:
            return "example.com"
    
    def _generate_tasks_from_llm(self, objectives: List[str], scope_str: str) -> List[Dict[str, Any]]:
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=(
                "You are a cybersecurity task planning assistant. "
                "Return a VALID JSON array of tasks, no extra text. "
                "Each task must have: name, description, tool, params, depends_on."
            )),
            HumanMessage(content=TASK_DECOMPOSITION_PROMPT.format(
                objective="\n".join(objectives),
                scope=scope_str
            ))
        ])

        chain = prompt | self.llm
        raw_output_obj = chain.invoke({})
        raw_output = getattr(raw_output_obj, "content", str(raw_output_obj)) or ""
        raw_output_clean = raw_output.strip()
        raw_output_clean = re.sub(r'^```(\w+)?', '', raw_output_clean)
        raw_output_clean = re.sub(r'```$', '', raw_output_clean)

        if not raw_output_clean.startswith('['):
            raw_output_clean = '[' + raw_output_clean
        if not raw_output_clean.endswith(']'):
            raw_output_clean = raw_output_clean + ']'

        logger.debug(f"Raw LLM output after cleanup:\n{raw_output_clean}")

        try:
            return extract_json_array(raw_output_clean)
        except Exception as json_error:
            logger.error(f"Failed to parse JSON from LLM output: {json_error}")
            logger.error(f"Raw output (truncated): {raw_output_clean[:500]}...")
            raise
    
    def _process_and_add_tasks(self, tasks_list: List[Dict[str, Any]], 
                                fallback_target: str, state: Dict[str, Any]) -> int:
        valid_tools = {"nmap", "gobuster", "ffuf", "sqlmap"}
        tasks_added = 0

        for task_data in tasks_list[:10]:
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

            duplicate = any(
                t.name == task_data["name"] and 
                t.tool == tool_name and 
                t.params.get("target") == params.get("target")
                for t in self.task_manager.get_all_tasks()
            )
            if duplicate:
                logger.info(f"Duplicate task '{task_data['name']}' for tool '{tool_name}' already exists; skipping.")
                continue

            target = params["target"]
            if not self.scope_validator.is_in_scope(target):
                if fallback_target.lower() in target.lower() or target.lower() in fallback_target.lower():
                    params["target"] = fallback_target
                    target = fallback_target
                else:
                    logger.warning(f"Skipping out-of-scope target: {target}")
                    continue

            task_id = str(uuid.uuid4())
            new_task = Task(
                id=task_id,
                name=task_data["name"],
                description=task_data["description"],
                tool=tool_name,
                params=params,
                depends_on=task_data.get("depends_on", [])
            )

            if self.scope_validator.is_in_scope(target):
                self.task_manager.add_task(new_task)
                tasks_added += 1
            else:
                logger.warning(f"Skipping out-of-scope target after normalization: {target}")

        return tasks_added
