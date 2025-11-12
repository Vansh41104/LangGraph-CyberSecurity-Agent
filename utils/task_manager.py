from enum import Enum
from typing import List, Dict, Any, Optional
import time
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"

class Task:
    def __init__(self, 
                 id: Optional[str] = None, 
                 name: str = "", 
                 tool: str = "", 
                 params: Optional[Dict[str, Any]] = None, 
                 description: str = "", 
                 max_retries: int = 3, 
                 depends_on: Optional[List[str]] = None):
        self.id = id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.tool = tool
        self.params = params or {}
        self.max_retries = max_retries
        self.depends_on = depends_on or []
        self.status = TaskStatus.PENDING
        self.retry_count = 0
        self.errors = []
        self.error = None
        self.logs = []
        self.result = None
        self.started_at = None
        self.completed_at = None
        self.created_at = datetime.now()

    def update_status(self, status: TaskStatus, result: Any = None, error: Any = None):
        self.status = status
        if status == TaskStatus.RUNNING and not self.started_at:
            self.started_at = datetime.now()
        elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED]:
            self.completed_at = datetime.now()
        if result is not None:
            self.result = result
        if error is not None:
            self.error = error
            self.logs.append(f"Error: {error}")

    def add_log(self, message: str) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        return log_entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "description": self.description,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "depends_on": self.depends_on,
            "logs": self.logs,
        }

class TaskManager:
    def __init__(self):
        self.tasks: List[Task] = []
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def get_current_time() -> datetime:
        return datetime.utcnow()

    def add_task(self, task: Task) -> str:
        self.tasks.append(task)
        self.logger.info(f"Added task: {task.name} (ID: {task.id})")
        return task.id

    def has_task(self, task_id: str) -> bool:
        return any(task.id == task_id for task in self.tasks)

    def get_task(self, task_id: str) -> Optional[Task]:
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None

    def get_all_tasks(self) -> List[Task]:
        return self.tasks

    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        return [task for task in self.tasks if task.status == status]

    def update_task(self, task: Task) -> None:
        self.logger.info(f"Updated task {task.id} status to {task.status.value}")

    def get_next_executable_task(self) -> Optional[Task]:
        for task in self.tasks:
            if task.status != TaskStatus.PENDING:
                continue

            if all(
                (self.get_task(dep_id) and self.get_task(dep_id).status == TaskStatus.COMPLETED)
                for dep_id in task.depends_on
            ):
                return task
        return None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskManager':
        task_manager = cls()
        tasks_data = data.get('tasks', [])
        for task_dict in tasks_data:
            task = task_manager.create_task_from_dict(task_dict)
            task_manager.add_task(task)
        return task_manager

    def create_task_from_dict(self, task_dict: Dict[str, Any]) -> Task:
        task = Task(
            id=task_dict.get("id"),
            name=task_dict["name"],
            tool=task_dict["tool"],
            params=task_dict["params"],
            description=task_dict.get("description", ""),
            max_retries=task_dict.get("max_retries", 3),
            depends_on=task_dict.get("depends_on", []),
        )
        return task

    def to_dict(self) -> Dict[str, Any]:
        return {"tasks": [task.to_dict() for task in self.tasks]}
