from typing import Dict, Any, List
import uuid
import logging

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage

from agents.base_agent import BaseAgent
from agents.task_decomposition_agent import extract_json_array
from utils.task_manager import Task, TaskStatus

logger = logging.getLogger(__name__)


RESULT_ANALYSIS_PROMPT = '''
You are an expert cybersecurity analyst. Analyze the following scan results and create follow-up tasks based on the findings.

ORIGINAL TASK: {task}
SCAN RESULTS: {results}
CURRENT TASKS: {current_tasks}
TARGET SCOPE: {scope}

Available tools:
1. nmap - For network mapping and port scanning
2. gobuster - For directory and file enumeration
3. ffuf - For web fuzzing to discover hidden endpoints
4. sqlmap - For testing SQL injection vulnerabilities

Create follow-up tasks based on the scan results. Focus on:
- Investigating discovered open ports and services
- Deeper investigation of potential vulnerabilities
- Confirming uncertain or partial results
- Expanding scope based on new information discovered

Each task should have:
- "name": A short descriptive name
- "description": A detailed explanation with reference to the original findings
- "tool": One of: "nmap", "gobuster", "ffuf", or "sqlmap"
- "params": Parameters specific to the tool, always including "target"
- "depends_on": List of task IDs this task depends on (can be empty)

IMPORTANT FORMATTING INSTRUCTIONS:
1. Your ENTIRE response must be ONLY a valid JSON array with no other text
2. Start with '[' and end with ']'
3. Do not include any explanation, markdown code blocks, or text outside the JSON array
4. Each object in the array must have exactly the fields shown in the examples
5. All field names must be in double quotes (e.g., "name", not name)
6. Do NOT include "id" fields - these will be generated automatically
7. Ensure all JSON syntax is correct (commas between objects, no trailing commas)
8. Return an empty array [] if no new tasks are needed
'''


class AnalysisAgent(BaseAgent):
    
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        try:
            task_id = state.get("current_task_id")
            if not task_id:
                return state
            
            task = self.task_manager.get_task(task_id)
            if not task or task.status != TaskStatus.COMPLETED:
                return state
            
            results = state.get("results", {}).get(task_id)
            if not results:
                state.setdefault("results", {})[task_id] = {
                    "status": "no_results",
                    "timestamp": self.task_manager.get_current_time().isoformat()
                }
                return state
            
            logger.info(f"Analyzing results for task {task_id}")
            return self._analyze_results_with_chunking(state, task, results)
            
        except Exception as e:
            logger.error(f"Error in analyze_results: {str(e)}")
            state.setdefault("error_log", []).append(f"Results analysis error: {str(e)}")
            return state
    
    def _analyze_results_with_chunking(self, state: Dict[str, Any], 
                                       task: Task, results: Any) -> Dict[str, Any]:
        try:
            results_summary = self._create_result_summary(results)
            results_summary = self.truncate_text(str(results_summary), 500)
            
            total_tasks = len(self.task_manager.get_all_tasks())
            current_tasks_summary = f"Total tasks: {total_tasks}"
            
            scope_str = self.truncate_text(self.get_scope_string(), 300)
            
            task_summary = {
                "name": task.name,
                "tool": task.tool,
                "params": task.params
            }
            task_summary_str = self.truncate_text(str(task_summary), 300)
            
            high_level_text = self._get_high_level_analysis(
                task_summary_str, results_summary, scope_str
            )
            
            followup_text = self._get_followup_tasks(
                task_summary_str, high_level_text, current_tasks_summary, scope_str
            )
            
            if task.result:
                if isinstance(task.result, dict):
                    task.result['analysis'] = {
                        'high_level': high_level_text,
                        'followup': followup_text
                    }
                else:
                    task.result = {
                        'data': task.result,
                        'analysis': {
                            'high_level': high_level_text,
                            'followup': followup_text
                        }
                    }
            try:
                new_tasks = extract_json_array(followup_text)
                self._process_new_tasks(new_tasks, state)
            except Exception as e:
                logger.warning(f"Error processing follow-up tasks: {str(e)}")
                state.setdefault("error_log", []).append(f"Follow-up task error: {str(e)}")
                
        except Exception as e:
            error_msg = f"Error analyzing results: {str(e)}"
            logger.error(error_msg)
            state.setdefault("error_log", []).append(error_msg)
        
        self.task_manager.update_task(task)
        return state
    
    def _get_high_level_analysis(self, task_summary: str, results_summary: str, 
                                  scope_str: str) -> str:
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity analyst reviewing scan results. Provide a concise analysis."),
                HumanMessage(content=f"""
                    Analyze these scan results summary to identify key security findings:

                    ORIGINAL TASK: {task_summary}
                    SCAN RESULTS SUMMARY: {results_summary}
                    TARGET SCOPE: {scope_str}

                    Respond with the 3-5 most important security observations in bullet points.
                """)
            ])
            
            chain = prompt | self.llm
            high_level_analysis = chain.invoke({})
            high_level_text = high_level_analysis.content if hasattr(high_level_analysis, "content") else str(high_level_analysis)
            return self.truncate_text(high_level_text, 300)
            
        except Exception as e:
            logger.warning(f"Error generating high-level analysis: {str(e)}")
            return "Analysis could not be generated."
    
    def _get_followup_tasks(self, task_summary: str, high_level_text: str,
                            current_tasks_summary: str, scope_str: str) -> str:
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a cybersecurity analyst who responds ONLY with valid JSON."),
                HumanMessage(content=f"""
                    Based on these scan findings, determine if any follow-up tasks are needed.

                    ORIGINAL TASK: {task_summary}
                    HIGH-LEVEL FINDINGS: {high_level_text}
                    CURRENT TASKS: {current_tasks_summary}
                    TARGET SCOPE: {scope_str}

                    IMPORTANT: Your ENTIRE response must be a valid JSON array, even if empty.

                    If new tasks are needed, return JSON in this EXACT format:
                    [
                    {{
                        "name": "Short task name",
                        "description": "Detailed description",
                        "tool": "nmap", 
                        "params": {{"target": "domain.com", "scan_type": "syn", "ports": "1-1000"}},
                        "depends_on": []
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
            
            chain = prompt | self.llm
            followup_result = chain.invoke({})
            followup_text = followup_result.content if hasattr(followup_result, "content") else str(followup_result)
            return self.truncate_text(followup_text, 500)
            
        except Exception as e:
            logger.warning(f"Error generating follow-up tasks: {str(e)}")
            return "[]"
    
    def _create_result_summary(self, results: Any) -> Dict[str, Any]:
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
                for host in results["hosts"][:3]:
                    host_summary = {
                        "address": host.get("address"),
                        "ports": len(host.get("ports", []))
                    }
                    summary["hosts"].append(host_summary)
            
            if "stats" in results:
                summary["stats"] = results["stats"]
            
            return summary
            
        except Exception as e:
            logger.error(f"Error creating result summary: {str(e)}")
            return {"error": f"Failed to summarize results: {str(e)}"}
    
    def _process_new_tasks(self, new_tasks: List[Dict[str, Any]], state: Dict[str, Any]):
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
            
            # Check for duplicates
            duplicate = any(
                t.name == task_data["name"] and 
                t.tool == task_data["tool"] and 
                t.params.get("target") == params.get("target")
                for t in existing_tasks
            )
            if duplicate:
                continue
            
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
