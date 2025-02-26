import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.task_manager import Task, TaskManager, TaskStatus

class TestTask:
    def test_task_initialization(self):
        """Test Task object initialization"""
        task = Task(description="Run nmap scan on example.com")
        
        assert task.description == "Run nmap scan on example.com"
        assert task.status == TaskStatus.PENDING
        assert task.retry_count == 0  # Changed from attempts to retry_count
        assert task.created_at is not None
        assert task.started_at is None
        assert task.completed_at is None
        assert task.result is None
        assert task.error is None  # Changed from error_message to error
    
    def test_update_status_running(self):
        """Test updating task status to running"""
        task = Task(description="Run nmap scan")
        task.update_status(TaskStatus.RUNNING)
        
        assert task.status == TaskStatus.RUNNING
        assert task.started_at is not None
        assert task.completed_at is None
    
    def test_update_status_completed(self):
        """Test updating task status to completed"""
        task = Task(description="Run nmap scan")
        task.update_status(TaskStatus.RUNNING)
        result = {"ports": [80, 443], "status": "open"}
        task.update_status(TaskStatus.COMPLETED, result=result)
        
        assert task.status == TaskStatus.COMPLETED
        assert task.result == result
        assert task.started_at is not None
        assert task.completed_at is not None
    
    def test_update_status_failed(self):
        """Test updating task status to failed"""
        task = Task(description="Run nmap scan")
        task.update_status(TaskStatus.RUNNING)
        error_message = "Connection timeout"
        task.update_status(TaskStatus.FAILED, error=error_message)
        
        assert task.status == TaskStatus.FAILED
        assert task.error == error_message
        assert task.logs[-1] == f"Error: {error_message}"
    
    def test_add_log(self):
        """Test adding log messages"""
        task = Task(description="Run nmap scan")
        log_message = "Starting scan"
        log_entry = task.add_log(log_message)
        
        assert log_message in log_entry
        assert log_entry in task.logs
    
    def test_to_dict(self):
        """Test converting task to dictionary"""
        task = Task(
            name="Network Scan",
            tool="nmap",
            params={"target": "example.com", "ports": "80,443"},
            description="Run nmap scan on example.com"
        )
        task_dict = task.to_dict()
        
        assert task_dict["id"] == task.id
        assert task_dict["name"] == "Network Scan"
        assert task_dict["tool"] == "nmap"
        assert task_dict["params"]["target"] == "example.com"
        assert task_dict["description"] == "Run nmap scan on example.com"
        assert task_dict["status"] == TaskStatus.PENDING.value


class TestTaskManager:
    def test_add_task(self):
        """Test adding a task to the manager"""
        manager = TaskManager()
        task = Task(name="Scan Task", description="Run nmap scan")
        task_id = manager.add_task(task)
        
        assert task_id == task.id
        assert task in manager.tasks
        assert len(manager.tasks) == 1
    
    def test_get_task(self):
        """Test retrieving a task by ID"""
        manager = TaskManager()
        task = Task(name="Scan Task", description="Run nmap scan")
        manager.add_task(task)
        
        retrieved_task = manager.get_task(task.id)
        assert retrieved_task == task
        
        nonexistent_task = manager.get_task("nonexistent-id")
        assert nonexistent_task is None
    
    def test_get_tasks_by_status(self):
        """Test filtering tasks by status"""
        manager = TaskManager()
        task1 = Task(name="Pending Task")
        task2 = Task(name="Running Task")
        task3 = Task(name="Completed Task")
        
        manager.add_task(task1)
        manager.add_task(task2)
        manager.add_task(task3)
        
        task2.update_status(TaskStatus.RUNNING)
        task3.update_status(TaskStatus.COMPLETED)
        
        pending_tasks = manager.get_tasks_by_status(TaskStatus.PENDING)
        running_tasks = manager.get_tasks_by_status(TaskStatus.RUNNING)
        completed_tasks = manager.get_tasks_by_status(TaskStatus.COMPLETED)
        
        assert len(pending_tasks) == 1
        assert pending_tasks[0] == task1
        assert len(running_tasks) == 1
        assert running_tasks[0] == task2
        assert len(completed_tasks) == 1
        assert completed_tasks[0] == task3
    
    def test_get_next_executable_task(self):
        """Test getting the next executable task"""
        manager = TaskManager()
        
        # Create tasks with dependencies
        task1 = Task(name="Task 1")
        task2 = Task(name="Task 2", depends_on=[task1.id])
        task3 = Task(name="Task 3", depends_on=[task2.id])
        
        manager.add_task(task1)
        manager.add_task(task2)
        manager.add_task(task3)
        
        # Task 1 should be the next executable (no dependencies)
        next_task = manager.get_next_executable_task()
        assert next_task == task1
        
        # Mark task1 as completed
        task1.update_status(TaskStatus.COMPLETED)
        
        # Task 2 should be the next executable now
        next_task = manager.get_next_executable_task()
        assert next_task == task2
        
        # Mark all tasks as completed
        task2.update_status(TaskStatus.COMPLETED)
        task3.update_status(TaskStatus.COMPLETED)
        
        # No more executable tasks
        next_task = manager.get_next_executable_task()
        assert next_task is None
    
    def test_create_task_from_dict(self):
        """Test creating a task from dictionary"""
        manager = TaskManager()
        task_dict = {
            "id": "test-id-123",
            "name": "Test Task",
            "tool": "nmap",
            "params": {"target": "example.com"},
            "description": "Test description",
            "max_retries": 5,
            "depends_on": ["task-id-456"]
        }
        
        task = manager.create_task_from_dict(task_dict)
        
        assert task.id == "test-id-123"
        assert task.name == "Test Task"
        assert task.tool == "nmap"
        assert task.params["target"] == "example.com"
        assert task.description == "Test description"
        assert task.max_retries == 5
        assert task.depends_on == ["task-id-456"]