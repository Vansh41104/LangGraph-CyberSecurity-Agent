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
        domain = domain.lower().strip()
        if domain.startswith("."):
            self.add_wildcard_domain(domain)
        else:
            if domain not in self.allowed_domains:
                self.allowed_domains.append(domain)
                logger.info(f"Added domain to scope: {domain}")
            else:
                logger.info(f"Domain {domain} is already in scope")

    def add_wildcard_domain(self, wildcard: str):
        wildcard = wildcard.lower().strip()
        if not wildcard.startswith("."):
            wildcard = "." + wildcard
        if wildcard not in self.wildcard_domains:
            self.wildcard_domains.append(wildcard)
            logger.info(f"Added wildcard domain to scope: {wildcard}")
        else:
            logger.info(f"Wildcard domain {wildcard} is already in scope")

    def add_ip(self, ip: str):
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            ip_str = str(ip_obj)
            if ip_str not in self.allowed_ips:
                self.allowed_ips.append(ip_str)
                logger.info(f"Added IP to scope: {ip_str}")
            else:
                logger.info(f"IP {ip_str} is already in scope")
        except ValueError as e:
            logger.error(f"Invalid IP format: {ip}. Error: {str(e)}")
            raise ValueError(f"Invalid IP format: {ip}")

    def add_ip_range(self, ip_range: str):
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            if network not in self.allowed_ips:
                self.allowed_ips.append(network)
                logger.info(f"Added IP range to scope: {ip_range}")
            else:
                logger.info(f"IP range {ip_range} is already in scope")
        except ValueError as e:
            logger.error(f"Invalid IP range format: {ip_range}. Error: {str(e)}")
            raise ValueError(f"Invalid IP range format: {ip_range}")

    def clear_scope(self):
        self.allowed_domains = []
        self.allowed_ips = []
        self.wildcard_domains = []
        logger.info("Cleared all scope definitions")

    def is_domain_in_scope(self, domain: str) -> bool:
        domain = domain.lower().strip()
        if domain in self.allowed_domains:
            return True
        for wildcard in self.wildcard_domains:
            if domain.endswith(wildcard):
                return True
        return False

    def is_ip_in_scope(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            ip_str = str(ip_obj)
            
            for item in self.allowed_ips:
                if isinstance(item, str):
                    if ip_str == item:
                        return True
                elif isinstance(item, ipaddress.IPv4Network):
                    if ip_obj in item:
                        return True
            return False
        except ValueError:
            logger.error(f"Invalid IP format for validation: {ip}")
            return False

    def is_target_in_scope(self, target: str) -> bool:
        target = target.lower().strip()
        if "://" in target:
            target = target.split("://")[1]
        target = target.split("/")[0]
        target = target.split(":")[0]
        
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", target):
            ip = target.split('/')[0]
            return self.is_ip_in_scope(ip)
        else:
            return self.is_domain_in_scope(target)

    def get_scope_summary(self) -> Dict[str, List[str]]:
        return {
            "domains": self.allowed_domains,
            "wildcard_domains": self.wildcard_domains,
            "ips": [str(ip) for ip in self.allowed_ips]
        }

    def load_scope_from_config(self, config: Dict[str, List[str]]):
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
        target = None
        if "params" in task:
            target = task["params"].get("target") or task["params"].get("domain") or task["params"].get("url")
        if not target:
            logger.warning(f"No target found in task: {task.get('name', 'unnamed')}")
            return False

        return self.is_target_in_scope(target)
        
    def is_in_scope(self, target: str) -> bool:
        return self.is_target_in_scope(target)
