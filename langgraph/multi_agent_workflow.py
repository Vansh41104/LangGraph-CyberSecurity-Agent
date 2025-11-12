from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import logging

from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END, START

from agents.task_decomposition_agent import TaskDecompositionAgent
from agents.execution_agent import ExecutionAgent
from agents.analysis_agent import AnalysisAgent
from agents.report_agent import ReportGenerationAgent
from utils.task_manager import TaskManager, TaskStatus
from utils.scope import ScopeValidator
from utils.logger import setup_logger

logger = logging.getLogger(__name__)


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


def get_llm(model="openai/gpt-oss-20b", temperature=0):
    return ChatGroq(model=model, temperature=temperature)


class MultiAgentWorkflow:
    
    def __init__(self, llm=None, parallel_execution: bool = True):
        self.llm = llm or get_llm()
        self.parallel_execution = parallel_execution

        self.task_manager = TaskManager()
        self.scope_validator = ScopeValidator()

        self.task_decomposition_agent = TaskDecompositionAgent(
            llm=self.llm,
            task_manager=self.task_manager,
            scope_validator=self.scope_validator
        )
        
        self.execution_agent = ExecutionAgent(
            llm=self.llm,
            task_manager=self.task_manager,
            scope_validator=self.scope_validator,
            parallel_execution=parallel_execution
        )
        
        self.analysis_agent = AnalysisAgent(
            llm=self.llm,
            task_manager=self.task_manager,
            scope_validator=self.scope_validator
        )
        
        self.report_agent = ReportGenerationAgent(
            llm=self.llm,
            task_manager=self.task_manager,
            scope_validator=self.scope_validator
        )

        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> StateGraph:
        workflow = StateGraph(AgentState)
        
        workflow.add_node("decompose_tasks", self._decompose_tasks_node)
        workflow.add_node("select_next_task", self._select_next_task_node)
        workflow.add_node("check_scope", self._check_scope_node)
        workflow.add_node("execute_task", self._execute_task_node)
        workflow.add_node("analyze_results", self._analyze_results_node)
        workflow.add_node("generate_report", self._generate_report_node)

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
    
    def _sync_state(self, state: AgentState):
        if isinstance(state.task_manager, dict) and state.task_manager:
            self.task_manager.from_dict(state.task_manager)
        
        for agent in [self.task_decomposition_agent, self.execution_agent, 
                      self.analysis_agent, self.report_agent]:
            agent.task_manager = self.task_manager
            agent.scope_validator = self.scope_validator
    
    def _update_state(self, state: AgentState):
        state.task_manager = self.task_manager.to_dict()
    
    def _decompose_tasks_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Decompose Tasks")
        self._sync_state(state)
        state = self.task_decomposition_agent.execute(dict(state))
        self._update_state(state)
        return state
    
    def _select_next_task_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Select Next Task")
        self._sync_state(state)
        
        try:
            next_task = self._get_next_executable_task()
            if next_task:
                state.current_task_id = next_task.id
                logger.info(f"Selected task: {next_task.name} (ID: {next_task.id})")
            else:
                state.current_task_id = None
                logger.info("No more tasks to execute")
        except Exception as e:
            logger.error(f"Error selecting next task: {str(e)}")
            state.error_log.append(f"Error selecting next task: {str(e)}")
            state.current_task_id = None
        
        self._update_state(state)
        return state
    
    def _check_scope_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Check Scope")
        self._sync_state(state)
        
        try:
            task_id = state.current_task_id
            if not task_id:
                return state
            
            task = self.task_manager.get_task(task_id)
            if not task:
                return state
            
            target = task.params.get("target") or task.params.get("target_url")
            if target:
                targets_to_check = [target] if isinstance(target, str) else target
                
                for t in targets_to_check:
                    if not self.scope_validator.is_in_scope(t):
                        task.status = TaskStatus.SKIPPED
                        self.task_manager.update_task(task)
                        logger.warning(f"Task {task_id} skipped: target {t} is out of scope")
                        break
        
        except Exception as e:
            logger.error(f"Error in check_scope: {str(e)}")
            state.error_log.append(f"Scope check error: {str(e)}")
        
        self._update_state(state)
        return state
    
    def _execute_task_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Execute Task")
        self._sync_state(state)
        state = self.execution_agent.execute(dict(state))
        self._update_state(state)
        return state
    
    def _analyze_results_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Analyze Results")
        self._sync_state(state)
        state = self.analysis_agent.execute(dict(state))
        self._update_state(state)
        return state
    
    def _generate_report_node(self, state: AgentState) -> AgentState:
        logger.info("Node: Generate Report")
        self._sync_state(state)
        state = self.report_agent.execute(dict(state))
        self._update_state(state)
        return state
    
    def _has_next_task(self, state: AgentState) -> bool:
        try:
            self._sync_state(state)
            pending_tasks = [t for t in self.task_manager.get_all_tasks() 
                            if t.status == TaskStatus.PENDING]
            has_next = len(pending_tasks) > 0
            logger.info(f"Has next task: {has_next} (found {len(pending_tasks)} pending tasks)")
            return has_next
        except Exception as e:
            logger.error(f"Error in has_next_task: {str(e)}")
            return False
    
    def _check_scope_condition(self, state: AgentState) -> bool:
        try:
            task_id = state.current_task_id
            if not task_id:
                return False
            
            self._sync_state(state)
            task = self.task_manager.get_task(task_id)
            if not task:
                return False
            
            return task.status != TaskStatus.SKIPPED
        except Exception as e:
            logger.error(f"Error in check_scope_condition: {str(e)}")
            return False
    
    def _get_next_executable_task(self):
        """Get the next task that can be executed"""
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
        
        logger.info(f"Starting multi-agent workflow with objectives: {objectives}")
        
        try:
            compiled_workflow = self.workflow.compile()
            compiled_workflow.recursion_limit = 10000
            final_state = compiled_workflow.invoke(
                initial_state, 
                config={"recursion_limit": 10000}
            )
            
            for field in ["results", "execution_log", "error_log"]:
                if field not in final_state:
                    final_state[field] = {} if field == "results" else []
            
            if "report" not in final_state or not final_state["report"]:
                logger.warning("No report found in final state, creating basic report")
                final_state["report"] = {
                    "content": "## Security Assessment Report\n\nThe assessment was completed.",
                    "timestamp": self.task_manager.get_current_time().isoformat()
                }
            
            logger.info("Workflow completed successfully")
            
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
                    "content": f"## Error Report\n\nWorkflow failed: {str(e)}",
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
        
        logger.info(f"Scope configured: {len(self.scope_validator.domains)} domains, "
                   f"{len(self.scope_validator.wildcard_domains)} wildcards, "
                   f"{len(self.scope_validator.ip_ranges)} IP ranges")
