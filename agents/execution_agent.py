from typing import Dict, Any, Optional, List
import logging
from concurrent.futures import ThreadPoolExecutor

from agents.base_agent import BaseAgent
from tools.security_tools import get_tool_by_name
from utils.task_manager import Task, TaskStatus

logger = logging.getLogger(__name__)


class ExecutionAgent(BaseAgent):
    
    def __init__(self, *args, parallel_execution: bool = True, max_workers: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self.parallel_execution = parallel_execution
        self.max_workers = max_workers
    
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        task_id = state.get("current_task_id")
        if not task_id:
            logger.info("No task ID provided, skipping execution")
            return state
        
        task = self.task_manager.get_task(task_id)
        if not task:
            logger.warning(f"Task {task_id} not found, skipping execution")
            return state
        
        if task.status == TaskStatus.SKIPPED:
            logger.info(f"Task {task_id} was skipped due to scope validation")
            return state
        
        try:
            if self.parallel_execution:
                parallel_tasks = self._get_parallel_executable_tasks(task)
            else:
                parallel_tasks = [task]
            
            logger.info(f"Executing {len(parallel_tasks)} tasks in parallel")
            
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(parallel_tasks))) as executor:
                future_to_task = {
                    executor.submit(self._execute_single_task, t): t 
                    for t in parallel_tasks
                }
                
                for future in future_to_task:
                    current_task = future_to_task[future]
                    try:
                        result, executed_task = future.result()
                        state.setdefault("results", {})[executed_task.id] = result

                        state.setdefault("execution_log", []).append({
                            "task_id": executed_task.id,
                            "task_name": executed_task.name,
                            "status": executed_task.status.value,
                            "tool": executed_task.tool
                        })
                        
                    except Exception as exc:
                        error_msg = f"Task {current_task.id} generated an exception: {exc}"
                        logger.error(error_msg)
                        state.setdefault("error_log", []).append(error_msg)
        
        except Exception as e:
            error_msg = f"Error in parallel execution for task {task_id}: {str(e)}"
            logger.error(error_msg)
            state.setdefault("error_log", []).append(error_msg)
        
        return state
    
    def _get_parallel_executable_tasks(self, primary_task: Task) -> List[Task]:
        parallel_tasks = [primary_task]
        
        for other_task in self.task_manager.get_all_tasks():
            if other_task.id == primary_task.id or other_task.status != TaskStatus.PENDING:
                continue
            
            deps_satisfied = all(
                self.task_manager.get_task(dep_id) and 
                self.task_manager.get_task(dep_id).status == TaskStatus.COMPLETED 
                for dep_id in other_task.depends_on
            )
            
            if deps_satisfied:
                parallel_tasks.append(other_task)
        
        return parallel_tasks
    
    def _execute_single_task(self, task: Task) -> tuple:
        result = None
        
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = self.task_manager.get_current_time()
            if not hasattr(task, 'errors'):
                task.errors = []
            self.task_manager.update_task(task)
            
            logger.info(f"Executing task: {task.name} (ID: {task.id}) with tool: {task.tool}")
            
            tool = get_tool_by_name(task.tool)
            if not tool:
                raise ValueError(f"Tool '{task.tool}' not found")
            
            params = self._prepare_task_params(task)
            
            logger.info(f"Executing {task.tool} scan with parameters: {params}")
            result = tool._run(**params)
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = self.task_manager.get_current_time()
            
        except Exception as e:
            error_msg = f"Error executing task {task.id} ({task.name}): {str(e)}"
            logger.error(error_msg)
            task.status = TaskStatus.FAILED
            task.errors.append(error_msg)
            task.retry_count = getattr(task, 'retry_count', 0) + 1
            
            if task.retry_count < getattr(task, 'max_retries', 3):
                task.status = TaskStatus.RETRYING
                logger.info(f"Task {task.id} will be retried, attempt {task.retry_count}")
        
        finally:
            self.task_manager.update_task(task)
        
        return result, task
    
    def _prepare_task_params(self, task: Task) -> Dict[str, Any]:
        params = task.params.copy()
        
        if not params.get("target") and not params.get("target_url"):
            raise ValueError("Target parameter is missing.")
        
        if "target" in params and isinstance(params["target"], str) and "," in params["target"]:
            params["target"] = [t.strip() for t in params["target"].split(",")]
        
        if task.tool in ["gobuster", "ffuf"]:
            params = self._prepare_web_fuzzing_params(params)
        elif task.tool == "sqlmap":
            params = self._prepare_sqlmap_params(params, task)
        elif task.tool == "nmap":
            params = self._prepare_nmap_params(params, task)
        
        params["timeout"] = min(params.get("timeout", 180), 300)
        
        return params
    
    def _prepare_web_fuzzing_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        default_wordlist_paths = [
            "/usr/share/wordlists/gobuster/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt"
        ]
        
        if "wordlist" not in params or not params["wordlist"]:
            for wordlist in default_wordlist_paths:
                try:
                    with open(wordlist, 'r'):
                        params["wordlist"] = wordlist
                        break
                except FileNotFoundError:
                    continue
            
            if "wordlist" not in params:
                raise ValueError("No valid wordlist found for web fuzzing")
        
        return params
    
    def _prepare_sqlmap_params(self, params: Dict[str, Any], task: Task) -> Dict[str, Any]:
        if "target" in params:
            params["target_url"] = params.pop("target")
        
        if "target_url" in params and not params["target_url"].startswith(('http://', 'https://')):
            params["target_url"] = f"http://{params['target_url']}"
        
        if getattr(task, 'retry_count', 0) == 0:
            params["dbs"] = True
            params["batch"] = True
            params.setdefault("timeout", 300)
        else:
            params["risk"] = "1"
            params["level"] = "1"
            params.pop("dump-all", None)
        
        return params
    
    def _prepare_nmap_params(self, params: Dict[str, Any], task: Task) -> Dict[str, Any]:
        if "ports" in params:
            port_range = params["ports"]
            try:
                if "-" in str(port_range):
                    start, end = map(int, str(port_range).split("-"))
                    if end > 9000:
                        params["ports"] = f"{start}-9000"
            except Exception as e:
                logger.warning(f"Could not parse port range: {e}")

        if "script_args" in params:
            params["arguments"] = params.pop("script_args")
        
        if "scan_type" in params:
            scan_type = params.pop("scan_type")
            if scan_type in ["ssh_vuln", "ssh_vulnerability"]:
                params.setdefault("arguments", "-sV --script ssh2-enum-algos")
            elif scan_type == "syn":
                params.setdefault("arguments", "-sS")
                
        if task.params.get("version_detection", False):
            current_args = params.get("arguments", "")
            if "-sV" not in current_args:
                params["arguments"] = f"{current_args} -sV".strip()
        
        return params
