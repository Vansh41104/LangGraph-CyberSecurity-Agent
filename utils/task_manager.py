from enum import Enum
from typing import List, Dict, Any, Optional, Callable
import time
import logging
from datetime import datetime


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Task:
    def __init__(
        self,
        name: str,
        tool: str,
        params: Dict[str, Any],
        description: str = "",
        max_retries: int = 3,
        depends_on: List[str] = None,
    ):
        self.id = f"{tool}_{int(time.time() * 1000)}"
        self.name = name
        self.tool = tool
        self.params = params
        self.description = description
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.retry_count = 0
        self.max_retries = max_retries
        self.depends_on = depends_on or []
        self.logs = []

    def update_status(self, status: TaskStatus, result=None, error=None):
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

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        return log_entry

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "description": self.description,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
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

    def add_task(self, task: Task) -> str:
        """Add a new task to the manager and return its ID."""
        self.tasks.append(task)
        self.logger.info(f"Added task: {task.name} (ID: {task.id})")
        return task.id

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by its ID."""
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None

    def get_all_tasks(self) -> List[Task]:
        """Get all tasks."""
        return self.tasks

    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        """Get all tasks with the specified status."""
        return [task for task in self.tasks if task.status == status]

    def update_task_status(
        self, task_id: str, status: TaskStatus, result=None, error=None
    ) -> bool:
        """Update the status of a task."""
        task = self.get_task(task_id)
        if task:
            task.update_status(status, result, error)
            self.logger.info(f"Updated task {task_id} status to {status.value}")
            return True
        self.logger.warning(f"Task {task_id} not found for status update")
        return False

    def retry_task(self, task_id: str) -> bool:
        """Retry a failed task if max retries not exceeded."""
        task = self.get_task(task_id)
        if not task:
            self.logger.warning(f"Task {task_id} not found for retry")
            return False

        if task.status != TaskStatus.FAILED:
            self.logger.warning(f"Cannot retry task {task_id} with status {task.status.value}")
            return False

        if task.retry_count >= task.max_retries:
            self.logger.warning(f"Max retries exceeded for task {task_id}")
            return False

        task.retry_count += 1
        task.status = TaskStatus.PENDING
        task.error = None
        task.add_log(f"Retry attempt {task.retry_count}/{task.max_retries}")
        self.logger.info(f"Retrying task {task_id} (attempt {task.retry_count}/{task.max_retries})")
        return True

    def get_next_executable_task(self) -> Optional[Task]:
        """Get the next task that can be executed (all dependencies satisfied)."""
        for task in self.tasks:
            if task.status != TaskStatus.PENDING:
                continue

            dependencies_met = True
            for dep_id in task.depends_on:
                dep_task = self.get_task(dep_id)
                if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                    dependencies_met = False
                    break

            if dependencies_met:
                return task
        return None

    def add_log_to_task(self, task_id: str, message: str) -> bool:
        """Add a log message to a task."""
        task = self.get_task(task_id)
        if task:
            log_entry = task.add_log(message)
            self.logger.debug(f"Task {task_id} log: {log_entry}")
            return True
        return False

    def create_task_from_dict(self, task_dict: Dict[str, Any]) -> Task:
        """Create a Task object from a dictionary."""
        task = Task(
            name=task_dict["name"],
            tool=task_dict["tool"],
            params=task_dict["params"],
            description=task_dict.get("description", ""),
            max_retries=task_dict.get("max_retries", 3),
            depends_on=task_dict.get("depends_on", []),
        )
        return task

    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate a summary report of all tasks."""
        completed = len(self.get_tasks_by_status(TaskStatus.COMPLETED))
        failed = len(self.get_tasks_by_status(TaskStatus.FAILED))
        pending = len(self.get_tasks_by_status(TaskStatus.PENDING))
        running = len(self.get_tasks_by_status(TaskStatus.RUNNING))
        skipped = len(self.get_tasks_by_status(TaskStatus.SKIPPED))

        tasks_summary = []
        for task in self.tasks:
            tasks_summary.append({
                "id": task.id,
                "name": task.name,
                "tool": task.tool,
                "status": task.status.value,
                "error": task.error,
                "retry_count": task.retry_count,
                "execution_time": (task.completed_at - task.started_at).total_seconds() if task.completed_at and task.started_at else None,
            })

        return {
            "total_tasks": len(self.tasks),
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "running": running,
            "skipped": skipped,
            "tasks": tasks_summary,
            "generated_at": datetime.now().isoformat(),
        }