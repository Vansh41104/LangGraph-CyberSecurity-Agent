from typing import Any, Dict, Optional
from abc import ABC, abstractmethod
import logging
from langchain_core.language_models import BaseChatModel
from utils.task_manager import TaskManager
from utils.scope import ScopeValidator

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    
    def __init__(self, llm: BaseChatModel, task_manager: Optional[TaskManager] = None, 
                 scope_validator: Optional[ScopeValidator] = None):
        self.llm = llm
        self.task_manager = task_manager or TaskManager()
        self.scope_validator = scope_validator or ScopeValidator()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    def truncate_text(self, text: str, max_length: int = 500) -> str:
        if not isinstance(text, str):
            text = str(text)
        if len(text) > max_length:
            return text[:max_length] + "..."
        return text
    
    def get_scope_string(self) -> str:
        domains = self.scope_validator.domains + self.scope_validator.wildcard_domains
        ip_ranges = self.scope_validator.ip_ranges
        scope_str = f"Domains: {', '.join(domains)}\nIP Ranges: {', '.join(map(str, ip_ranges))}"
        return scope_str
