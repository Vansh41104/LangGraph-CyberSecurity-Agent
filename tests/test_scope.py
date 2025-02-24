import pytest
import sys
import os
from unittest.mock import patch

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scope import ScopeValidator

class TestScopeValidator:
    def test_init_with_empty_lists(self):
        """Test initializing with empty lists for both domains and IP ranges"""
        validator = ScopeValidator(domains=[], ip_ranges=[])
        assert validator.domains == []
        assert validator.ip_ranges == []
    
    def test_init_with_valid_domains(self):
        """Test initializing with valid domains"""
        domains = ["example.com", "test.org", "*.wildcard.net"]
        validator = ScopeValidator(domains=domains, ip_ranges=[])
        assert validator.domains == domains
    
    def test_init_with_valid_ip_ranges(self):
        """Test initializing with valid IP ranges"""
        ip_ranges = ["192.168.1.0/24", "10.0.0.1", "172.16.0.0/16"]
        validator = ScopeValidator(domains=[], ip_ranges=ip_ranges)
        assert validator.ip_ranges == ip_ranges
    
    def test_normalize_domain(self):
        """Test domain normalization"""
        validator = ScopeValidator([], [])
        
        assert validator._normalize_domain("EXAMPLE.COM") == "example.com"
        assert validator._normalize_domain("  test.org  ") == "test.org"
        assert validator._normalize_domain("*.wildcard.net") == "*.wildcard.net"
        assert validator._normalize_domain("https://secure.com") == "secure.com"
        assert validator._normalize_domain("http://www.site.io") == "www.site.io"
        assert validator._normalize_domain("subdomain.example.com") == "subdomain.example.com"
    
    def test_is_domain_in_scope(self):
        """Test domain scope validation"""
        validator = ScopeValidator(
            domains=["example.com", "test.org", "*.wildcard.net"],
            ip_ranges=[]
        )
        
        # Exact matches
        assert validator.is_domain_in_scope("example.com") is True
        assert validator.is_domain_in_scope("test.org") is True
        
        # Subdomain matches
        assert validator.is_domain_in_scope("www.example.com") is True
        assert validator.is_domain_in_scope("api.example.com") is True
        
        # Wildcard matches
        assert validator.is_domain_in_scope("sub.wildcard.net") is True
        assert validator.is_domain_in_scope("test.wildcard.net") is True
        
        # Out of scope
        assert validator.is_domain_in_scope("malicious.com") is False
        assert validator.is_domain_in_scope("example.net") is False
        assert validator.is_domain_in_scope("wildcard.com") is False
    
    def test_is_ip_in_scope(self):
        """Test IP scope validation"""
        validator = ScopeValidator(
            domains=[],
            ip_ranges=["192.168.1.0/24", "10.0.0.1", "172.16.0.0/16"]
        )
        
        # Single IP match
        assert validator.is_ip_in_scope("10.0.0.1") is True
        
        # CIDR range matches
        assert validator.is_ip_in_scope("192.168.1.100") is True
        assert validator.is_ip_in_scope("192.168.1.254") is True
        assert validator.is_ip_in_scope("172.16.5.10") is True
        
        # Out of scope
        assert validator.is_ip_in_scope("192.168.2.1") is False
        assert validator.is_ip_in_scope("8.8.8.8") is False
        assert validator.is_ip_in_scope("10.0.0.2") is False
    
    def test_is_target_in_scope(self):
        """Test general target scope validation"""
        validator = ScopeValidator(
            domains=["example.com", "*.test.org"],
            ip_ranges=["192.168.1.0/24"]
        )
        
        # Domain targets
        assert validator.is_target_in_scope("example.com") is True
        assert validator.is_target_in_scope("api.example.com") is True
        assert validator.is_target_in_scope("sub.test.org") is True
        
        # IP targets
        assert validator.is_target_in_scope("192.168.1.100") is True
        
        # Out of scope
        assert validator.is_target_in_scope("malicious.com") is False
        assert validator.is_target_in_scope("8.8.8.8") is False
    
    def test_add_domain_to_scope(self):
        """Test adding a domain to the scope"""
        validator = ScopeValidator(["example.com"], [])
        validator.add_domain_to_scope("newdomain.com")
        
        assert "newdomain.com" in validator.domains
        assert validator.is_domain_in_scope("newdomain.com") is True
    
    def test_add_ip_range_to_scope(self):
        """Test adding an IP range to the scope"""
        validator = ScopeValidator([], ["192.168.1.0/24"])
        validator.add_ip_range_to_scope("10.0.0.0/24")
        
        assert "10.0.0.0/24" in validator.ip_ranges
        assert validator.is_ip_in_scope("10.0.0.5") is True
    
    def test_invalid_ip_format(self):
        """Test handling of invalid IP formats"""
        validator = ScopeValidator([], ["192.168.1.0/24"])
        
        # Invalid IP format
        assert validator.is_ip_in_scope("not.an.ip.address") is False
        assert validator.is_ip_in_scope("300.168.1.1") is False
    
    def test_scope_validation_with_url(self):
        """Test scope validation with URLs"""
        validator = ScopeValidator(["example.com"], ["192.168.1.0/24"])
        
        # URLs should be normalized
        assert validator.is_target_in_scope("https://example.com/path") is True
        assert validator.is_target_in_scope("http://api.example.com:8080/resource") is True
    
    @patch('utils.scope.ipaddress.ip_network')
    def test_ip_network_error_handling(self, mock_ip_network):
        """Test handling of errors from ipaddress module"""
        mock_ip_network.side_effect = ValueError("Invalid IP network")
        
        validator = ScopeValidator([], ["192.168.1.0/24"])
        assert validator.is_ip_in_scope("192.168.1.100") is False