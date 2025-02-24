import re
import ipaddress
from typing import List, Dict, Any, Optional, Union
import logging

logger = logging.getLogger(__name__)

class ScopeValidator:
    def __init__(self):
        self.allowed_domains: List[str] = []
        self.allowed_ips: List[Union[str, ipaddress.IPv4Network]] = []
        self.wildcard_domains: List[str] = []
        
    def add_domain(self, domain: str):
        """Add a domain to the allowed scope."""
        if domain.startswith("."):
            # This is a wildcard domain
            self.wildcard_domains.append(domain)
            logger.info(f"Added wildcard domain to scope: {domain}")
        else:
            self.allowed_domains.append(domain)
            logger.info(f"Added domain to scope: {domain}")
            
    def add_ip(self, ip: str):
        """Add an IP or IP range to the allowed scope."""
        try:
            # Check if it's a CIDR notation (network range)
            if "/" in ip:
                network = ipaddress.IPv4Network(ip, strict=False)
                self.allowed_ips.append(network)
                logger.info(f"Added IP range to scope: {ip}")
            else:
                # Single IP
                ip_obj = ipaddress.IPv4Address(ip)
                self.allowed_ips.append(str(ip_obj))
                logger.info(f"Added IP to scope: {ip}")
        except ValueError as e:
            logger.error(f"Invalid IP format: {ip}. Error: {str(e)}")
            raise ValueError(f"Invalid IP format: {ip}")

    def clear_scope(self):
        """Clear the current scope."""
        self.allowed_domains = []
        self.allowed_ips = []
        self.wildcard_domains = []
        logger.info("Cleared all scope definitions")
        
    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is within the defined scope."""
        # Check direct domain match
        if domain in self.allowed_domains:
            return True
            
        # Check wildcard domains
        for wildcard in self.wildcard_domains:
            if domain.endswith(wildcard):
                return True
                
        return False
        
    def is_ip_in_scope(self, ip: str) -> bool:
        """Check if an IP is within the defined scope."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            # Check direct IP match
            if str(ip_obj) in self.allowed_ips:
                return True
                
            # Check if IP is in any of the allowed networks
            for network in self.allowed_ips:
                if isinstance(network, ipaddress.IPv4Network) and ip_obj in network:
                    return True
                    
            return False
        except ValueError:
            logger.error(f"Invalid IP format for validation: {ip}")
            return False
            
    def is_target_in_scope(self, target: str) -> bool:
        """
        Check if a target (domain or IP) is within the defined scope.
        
        Args:
            target: A domain name or IP address to check
            
        Returns:
            bool: True if the target is within scope, False otherwise
        """
        # Check if it's an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", target):
            # Remove CIDR notation if present for single IP check
            ip = target.split('/')[0] if '/' in target else target
            return self.is_ip_in_scope(ip)
        else:
            # Assume it's a domain
            return self.is_domain_in_scope(target)
            
    def get_scope_summary(self) -> Dict[str, List[str]]:
        """Get a summary of the current scope."""
        return {
            "domains": self.allowed_domains,
            "wildcard_domains": self.wildcard_domains,
            "ips": [str(ip) for ip in self.allowed_ips]
        }
        
    def load_scope_from_config(self, config: Dict[str, List[str]]):
        """
        Load scope from a configuration dictionary.
        
        Args:
            config: Dictionary with keys 'domains' and 'ips' containing lists of allowed targets
        """
        self.clear_scope()
        
        # Add domains
        for domain in config.get("domains", []):
            self.add_domain(domain)
            
        # Add IPs
        for ip in config.get("ips", []):
            self.add_ip(ip)
            
        logger.info(f"Loaded scope from config: {len(self.allowed_domains)} domains, {len(self.allowed_ips)} IPs/ranges")

    def validate_task_target(self, task: Dict[str, Any]) -> bool:
        """
        Validate if the target in a task is within the defined scope.
        
        Args:
            task: A task dictionary with parameters
            
        Returns:
            bool: True if the task's target is within scope, False otherwise
        """
        # Extract target from task parameters
        target = None
        if "params" in task:
            target = task["params"].get("target") or task["params"].get("domain") or task["params"].get("url")
            
        if not target:
            logger.warning(f"No target found in task: {task.get('name', 'unnamed')}")
            return False
            
        # Clean the target (remove protocol, path, etc.)
        if "://" in target:
            target = target.split("://")[1]
        target = target.split("/")[0]  # Remove any path
        target = target.split(":")[0]  # Remove port if present
        
        is_in_scope = self.is_target_in_scope(target)
        if not is_in_scope:
            logger.warning(f"Target '{target}' is out of scope for task: {task.get('name', 'unnamed')}")
        
        return is_in_scope