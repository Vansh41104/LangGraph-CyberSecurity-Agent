import pytest
import sys
import os
import time
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
        assert task.attempts == 0
        assert task.created_at is not None
        assert task.started_at is None
        assert task.completed_at is None
        assert task.result is None
        assert task.error_message is None
    
    def test_start_task(self):
        """Test starting a task"""
        task = Task(description="Run nmap scan")
        task.start()
        
        assert task.status == TaskStatus.RUNNING
        assert task.attempts == 1
        assert task.started_at is not None
    
    def test_complete_task(self):
        """Test completing a task"""
        task = Task(description="Run nmap scan")
        task.start()
        result = {"ports": [80, 443], "status": "open"}
        task.complete(result)
        
        assert task.status == TaskStatus.COMPLETED
        assert task.result == result
        assert task.completed_at is not None
    
    def test_fail_task(self):
        """Test failing a task"""
        task = Task(description="Run nmap scan")
        task.start()
        error_message = "Connection timeout"
        task.fail(error_message)
        
        assert task.status == TaskStatus.FAILED
        assert task.error_message == error_message