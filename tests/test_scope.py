import pytest
import sys
import os
import ipaddress
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scope import ScopeValidator

@pytest.fixture
def empty_validator():
    """Fixture for an empty ScopeValidator"""
    return ScopeValidator()

@pytest.fixture
def populated_validator():
    """Fixture for a pre-populated ScopeValidator with domains and IPs"""
    validator = ScopeValidator()
    # Add regular domains
    validator.add_domain("example.com")
    validator.add_domain("test.org")
    
    # Add wildcard domain
    validator.add_wildcard_domain(".wildcard.net")
    
    # Add IP address
    validator.add_ip("10.0.0.1")
    
    # Add IP range
    validator.add_ip_range("192.168.1.0/24")
    validator.add_ip_range("172.16.0.0/16")
    
    return validator

class TestScopeValidator:
    def test_initialization(self):
        """Test initializing a ScopeValidator"""
        validator = ScopeValidator()
        
        assert validator.allowed_domains == []
        assert validator.allowed_ips == []
        assert validator.wildcard_domains == []
        assert validator.enabled is True
        
        # Test property getters
        assert validator.domains == []
        assert validator.ip_ranges == []
    
    def test_add_domain(self, empty_validator):
        """Test adding a regular domain"""
        validator = empty_validator
        
        validator.add_domain("example.com")
        assert "example.com" in validator.allowed_domains
        assert len(validator.allowed_domains) == 1
        
        # Add another domain
        validator.add_domain("test.org")
        assert "test.org" in validator.allowed_domains
        assert len(validator.allowed_domains) == 2
    
    def test_add_wildcard_domain(self, empty_validator):
        """Test adding wildcard domains with and without leading dot"""
        validator = empty_validator
        
        # With dot prefix
        validator.add_wildcard_domain(".example.com")
        assert ".example.com" in validator.wildcard_domains
        assert len(validator.wildcard_domains) == 1
        
        # Without dot prefix (should add the dot)
        validator.add_wildcard_domain("test.org")
        assert ".test.org" in validator.wildcard_domains
        assert len(validator.wildcard_domains) == 2
        
        # Test automatic conversion via add_domain
        validator.add_domain(".wildcard.net")
        assert ".wildcard.net" in validator.wildcard_domains
        assert len(validator.wildcard_domains) == 3
    
    def test_add_ip(self, empty_validator):
        """Test adding a single IP address"""
        validator = empty_validator
        
        validator.add_ip("192.168.1.1")
        assert "192.168.1.1" in validator.allowed_ips
        assert len(validator.allowed_ips) == 1
        
        # Test with different IP format
        validator.add_ip("10.0.0.1")
        assert "10.0.0.1" in validator.allowed_ips
        assert len(validator.allowed_ips) == 2
    
    def test_add_invalid_ip(self, empty_validator):
        """Test adding an invalid IP address"""
        validator = empty_validator
        
        with pytest.raises(ValueError, match=r"Invalid IP format:.*"):
            validator.add_ip("not.an.ip.address")
        
        with pytest.raises(ValueError, match=r"Invalid IP format:.*"):
            validator.add_ip("300.168.1.1")
    
    def test_add_ip_range(self, empty_validator):
        """Test adding IP ranges in CIDR notation"""
        validator = empty_validator
        
        validator.add_ip_range("192.168.1.0/24")
        assert len(validator.allowed_ips) == 1
        assert isinstance(validator.allowed_ips[0], ipaddress.IPv4Network)
        assert str(validator.allowed_ips[0]) == "192.168.1.0/24"
        
        # Add another range
        validator.add_ip_range("10.0.0.0/16")
        assert len(validator.allowed_ips) == 2
        assert str(validator.allowed_ips[1]) == "10.0.0.0/16"
    
    def test_add_invalid_ip_range(self, empty_validator):
        """Test adding an invalid IP range"""
        validator = empty_validator
        
        with pytest.raises(ValueError, match=r"Invalid IP range format:.*"):
            validator.add_ip_range("not-a-valid-cidr")
            
        with pytest.raises(ValueError, match=r"Invalid IP range format:.*"):
            validator.add_ip_range("300.168.1.0/24")
    
    def test_clear_scope(self, populated_validator):
        """Test clearing all scope definitions"""
        validator = populated_validator
        
        # Verify validator is populated first
        assert len(validator.domains) > 0
        assert len(validator.ip_ranges) > 0
        assert len(validator.wildcard_domains) > 0
        
        validator.clear_scope()
        
        # Verify everything is cleared
        assert validator.allowed_domains == []
        assert validator.allowed_ips == []
        assert validator.wildcard_domains == []
    
    def test_is_domain_in_scope(self, populated_validator):
        """Test checking if domains are in scope"""
        validator = populated_validator
        
        # Direct matches
        assert validator.is_domain_in_scope("example.com") is True
        assert validator.is_domain_in_scope("test.org") is True
        
        # Wildcard matches
        assert validator.is_domain_in_scope("sub.wildcard.net") is True
        assert validator.is_domain_in_scope("test.wildcard.net") is True
        
        # Out of scope
        assert validator.is_domain_in_scope("malicious.com") is False
        assert validator.is_domain_in_scope("example.net") is False
        assert validator.is_domain_in_scope("wildcard.com") is False
    
    def test_is_ip_in_scope(self, populated_validator):
        """Test checking if IPs are in scope"""
        validator = populated_validator
        
        # Direct match
        assert validator.is_ip_in_scope("10.0.0.1") is True
        
        # CIDR range matches
        assert validator.is_ip_in_scope("192.168.1.100") is True
        assert validator.is_ip_in_scope("192.168.1.254") is True
        assert validator.is_ip_in_scope("172.16.5.10") is True
        
        # Out of scope
        assert validator.is_ip_in_scope("192.168.2.1") is False
        assert validator.is_ip_in_scope("8.8.8.8") is False
        assert validator.is_ip_in_scope("10.0.0.2") is False
        
        # Invalid IP format
        assert validator.is_ip_in_scope("not.an.ip.address") is False
    
    def test_is_target_in_scope(self, populated_validator):
        """Test checking if targets (domain or IP) are in scope"""
        validator = populated_validator
        
        # Domain targets
        assert validator.is_target_in_scope("example.com") is True
        assert validator.is_target_in_scope("sub.wildcard.net") is True
        
        # IP targets
        assert validator.is_target_in_scope("10.0.0.1") is True
        assert validator.is_target_in_scope("192.168.1.100") is True
        
        # Out of scope
        assert validator.is_target_in_scope("malicious.com") is False
        assert validator.is_target_in_scope("8.8.8.8") is False
    
    def test_is_in_scope_alias(self, populated_validator):
        """Test that is_in_scope is an alias for is_target_in_scope"""
        validator = populated_validator
        
        # Check a few targets with both methods to confirm they're equivalent
        test_targets = ["example.com", "sub.wildcard.net", "10.0.0.1", "8.8.8.8"]
        
        for target in test_targets:
            assert validator.is_in_scope(target) == validator.is_target_in_scope(target)
    
    def test_get_scope_summary(self, populated_validator):
        """Test getting a summary of the current scope"""
        validator = populated_validator
        
        summary = validator.get_scope_summary()
        
        assert "domains" in summary
        assert "wildcard_domains" in summary
        assert "ips" in summary
        
        assert "example.com" in summary["domains"]
        assert "test.org" in summary["domains"]
        assert ".wildcard.net" in summary["wildcard_domains"]
        
        # IP addresses and ranges should be converted to strings
        assert any("10.0.0.1" in ip for ip in summary["ips"])
        assert any("192.168.1.0/24" in ip for ip in summary["ips"])
    
    def test_load_scope_from_config(self, empty_validator):
        """Test loading scope from a configuration dictionary"""
        validator = empty_validator
        
        config = {
            "domains": ["example.com", "test.org"],
            "wildcard_domains": [".wildcard.net", "wildcard.org"],
            "ips": ["10.0.0.1", "192.168.1.0/24"]
        }
        
        validator.load_scope_from_config(config)
        
        # Check domains were loaded
        assert "example.com" in validator.allowed_domains
        assert "test.org" in validator.allowed_domains
        
        # Check wildcard domains were loaded
        assert ".wildcard.net" in validator.wildcard_domains
        assert ".wildcard.org" in validator.wildcard_domains
        
        # Check IPs were loaded
        assert "10.0.0.1" in validator.allowed_ips
        assert any(str(ip) == "192.168.1.0/24" for ip in validator.allowed_ips)
    
    def test_validate_task_target(self, populated_validator):
        """Test validating tasks with targets"""
        validator = populated_validator
        
        # Valid task with target in params
        valid_task = {
            "name": "Test Scan",
            "params": {"target": "example.com"}
        }
        assert validator.validate_task_target(valid_task) is True
        
        # Valid task with domain in params
        valid_task_domain = {
            "name": "Domain Scan",
            "params": {"domain": "sub.wildcard.net"}
        }
        assert validator.validate_task_target(valid_task_domain) is True
        
        # Valid task with URL in params
        valid_task_url = {
            "name": "URL Scan",
            "params": {"url": "https://example.com/path"}
        }
        assert validator.validate_task_target(valid_task_url) is True
        
        # Task with target out of scope
        invalid_task = {
            "name": "Malicious Scan",
            "params": {"target": "malicious.com"}
        }
        assert validator.validate_task_target(invalid_task) is False
        
        # Task with no target
        no_target_task = {
            "name": "No Target Scan",
            "params": {"other": "value"}
        }
        assert validator.validate_task_target(no_target_task) is False
    
    def test_validate_task_with_url_parts(self, populated_validator):
        """Test validating tasks with URLs containing protocols, paths, ports"""
        validator = populated_validator
        
        # URL with protocol
        task1 = {
            "name": "Protocol Test",
            "params": {"url": "https://example.com"}
        }
        assert validator.validate_task_target(task1) is True
        
        # URL with protocol, path and port
        task2 = {
            "name": "Full URL Test",
            "params": {"url": "https://example.com:8080/path/to/resource?param=value"}
        }
        assert validator.validate_task_target(task2) is True
        
        # URL with protocol, invalid domain
        task3 = {
            "name": "Invalid Domain Test",
            "params": {"url": "https://malicious.com:8080/path"}
        }
        assert validator.validate_task_target(task3) is False