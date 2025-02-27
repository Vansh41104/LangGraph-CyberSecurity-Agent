import re
import ipaddress
from typing import List, Dict, Any, Union
import logging

logger = logging.getLogger(__name__)

class ScopeValidator:
    def __init__(self):
        self.allowed_domains: List[str] = []
        self.allowed_ips: List[Union[str, ipaddress.IPv4Network]] = []
        self.wildcard_domains: List[str] = []
        self.enabled: bool = True

    @property
    def domains(self) -> List[str]:
        return self.allowed_domains

    @property
    def ip_ranges(self) -> List[Union[str, ipaddress.IPv4Network]]:
        return self.allowed_ips

    def add_domain(self, domain: str):
        """Add a domain to the allowed scope.
        
        If the domain starts with a dot, it will be treated as a wildcard and passed to add_wildcard_domain.
        """
        domain = domain.lower().strip()
        if domain.startswith("."):
            self.add_wildcard_domain(domain)
        else:
            self.allowed_domains.append(domain)
            logger.info(f"Added domain to scope: {domain}")

    def add_wildcard_domain(self, wildcard: str):
        """Add a wildcard domain to the allowed scope.
        
        The wildcard should start with a dot (e.g. '.example.com').
        """
        wildcard = wildcard.lower().strip()
        if not wildcard.startswith("."):
            wildcard = "." + wildcard
        self.wildcard_domains.append(wildcard)
        logger.info(f"Added wildcard domain to scope: {wildcard}")

    def add_ip(self, ip: str):
        """Add a single IP to the allowed scope."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            ip_str = str(ip_obj)
            self.allowed_ips.append(ip_str)
            logger.info(f"Added IP to scope: {ip_str}")
        except ValueError as e:
            logger.error(f"Invalid IP format: {ip}. Error: {str(e)}")
            raise ValueError(f"Invalid IP format: {ip}")

    def add_ip_range(self, ip_range: str):
        """Add an IP range (in CIDR notation) to the allowed scope."""
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            self.allowed_ips.append(network)
            logger.info(f"Added IP range to scope: {ip_range}")
        except ValueError as e:
            logger.error(f"Invalid IP range format: {ip_range}. Error: {str(e)}")
            raise ValueError(f"Invalid IP range format: {ip_range}")

    def clear_scope(self):
        """Clear all scope definitions."""
        self.allowed_domains = []
        self.allowed_ips = []
        self.wildcard_domains = []
        logger.info("Cleared all scope definitions")

    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is within the allowed scope."""
        domain = domain.lower().strip()
        if domain in self.allowed_domains:
            return True
        for wildcard in self.wildcard_domains:
            if domain.endswith(wildcard):
                return True
        return False

    def is_ip_in_scope(self, ip: str) -> bool:
        """Check if an IP is within the allowed scope."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            ip_str = str(ip_obj)
            # Check for a direct IP match (if stored as a string)
            if ip_str in self.allowed_ips:
                return True
            # Check if IP falls within any allowed IP range
            for network in self.allowed_ips:
                if isinstance(network, ipaddress.IPv4Network) and ip_obj in network:
                    return True
            return False
        except ValueError:
            logger.error(f"Invalid IP format for validation: {ip}")
            return False

    def is_target_in_scope(self, target: str) -> bool:
        """
        Check if a target (domain or IP) is within the allowed scope.
        
        Args:
            target (str): A domain name or IP address.
        
        Returns:
            bool: True if the target is within scope, False otherwise.
        """
        target = target.lower().strip()
        # Remove protocol, path, and port if present
        if "://" in target:
            target = target.split("://")[1]
        target = target.split("/")[0]
        target = target.split(":")[0]
        
        # If the target looks like an IP (optionally with CIDR notation), check IP scope
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", target):
            ip = target.split('/')[0]  # Remove any CIDR notation for validation
            return self.is_ip_in_scope(ip)
        else:
            return self.is_domain_in_scope(target)

    def get_scope_summary(self) -> Dict[str, List[str]]:
        """Return a summary of the current scope."""
        return {
            "domains": self.allowed_domains,
            "wildcard_domains": self.wildcard_domains,
            "ips": [str(ip) for ip in self.allowed_ips]  # Convert networks to strings
        }

    def load_scope_from_config(self, config: Dict[str, List[str]]):
        """
        Load scope definitions from a configuration dictionary.
        
        The config dictionary can have the following keys:
          - 'domains': a list of domain names.
          - 'wildcard_domains': a list of wildcard domains.
          - 'ips': a list of IPs or CIDR ranges.
        
        Args:
            config (Dict[str, List[str]]): The configuration dictionary.
        """
        self.clear_scope()
        for domain in config.get("domains", []):
            self.add_domain(domain)
        for wildcard in config.get("wildcard_domains", []):
            self.add_wildcard_domain(wildcard)
        for ip in config.get("ips", []):
            if "/" in ip:
                self.add_ip_range(ip)
            else:
                self.add_ip(ip)
        logger.info(f"Loaded scope from config: {len(self.allowed_domains)} domains, {len(self.allowed_ips)} IPs/ranges")

    def validate_task_target(self, task: Dict[str, Any]) -> bool:
        """
        Validate if the target in a task is within the allowed scope.
        
        Args:
            task (Dict[str, Any]): A task dictionary with a 'params' key that may contain target information.
        
        Returns:
            bool: True if the task's target is within scope, False otherwise.
        """
        target = None
        if "params" in task:
            target = task["params"].get("target") or task["params"].get("domain") or task["params"].get("url")
        if not target:
            logger.warning(f"No target found in task: {task.get('name', 'unnamed')}")
            return False

        # Normalize and validate the target
        return self.is_target_in_scope(target)
        
    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is within the allowed scope.
        This is an alias for is_target_in_scope.
        
        Args:
            target (str): A domain name or IP address.
        
        Returns:
            bool: True if the target is within scope, False otherwise.
        """
        return self.is_target_in_scope(target)
