import subprocess
import json
import tempfile
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple
import ipaddress
import socket
from pathlib import Path
import re

from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class NmapScanner:
    """
    Wrapper for nmap security scanner.
    """
    
    def __init__(self, binary_path: str = "nmap"):
        """
        Initialize the NmapScanner.
        
        Args:
            binary_path: Path to the nmap binary
        """
        self.binary_path = binary_path
        self.verify_installation()
        
    def verify_installation(self):
        """Verify that nmap is installed and available."""
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            logger.info(f"Nmap version: {result.stdout.split('\\n')[0]}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap installation verification failed: {str(e)}")
            raise RuntimeError("Nmap is not properly installed or accessible")
    
    @retry_operation(max_retries=2)
    def scan(
        self,
        target: str,
        ports: str = None,
        arguments: str = "-sV -sC",
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Run an nmap scan against a target.
        
        Args:
            target: The target to scan (IP or domain)
            ports: The ports to scan (e.g., "22,80,443" or "1-1000")
            arguments: Additional nmap arguments
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Parsed scan results
        """
        # Create a temporary file for XML output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_file:
            xml_output_path = tmp_file.name
        
        try:
            # Build the nmap command
            cmd = [self.binary_path, "-oX", xml_output_path]
            
            # Add ports if specified
            if ports:
                cmd.extend(["-p", ports])
            
            # Add additional arguments
            if arguments:
                cmd.extend(arguments.split())
            
            # Add the target
            cmd.append(target)
            
            command_str = " ".join(cmd)
            logger.info(f"Executing nmap scan: {command_str}")
            
            # Execute the scan
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Check for errors
            if process.returncode != 0:
                error_msg = f"Nmap scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Parse the XML output
            scan_results = self._parse_xml_output(xml_output_path)
            
            # Add raw command and command output to results
            scan_results["command"] = command_str
            scan_results["stdout"] = process.stdout
            scan_results["stderr"] = process.stderr
            
            return scan_results
        
        finally:
            # Clean up the temporary file
            if os.path.exists(xml_output_path):
                os.unlink(xml_output_path)
    
    def _parse_xml_output(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse nmap XML output file.
        
        Args:
            xml_file: Path to the XML output file
            
        Returns:
            dict: Parsed scan results
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                "scan_info": {},
                "hosts": []
            }
            
            # Parse scan information
            if root.find("scaninfo") is not None:
                scan_info = root.find("scaninfo").attrib
                results["scan_info"] = scan_info
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = {
                    "status": host.find("status").attrib,
                    "addresses": [],
                    "hostnames": [],
                    "ports": []
                }
                
                # Parse addresses
                for addr in host.findall("address"):
                    host_data["addresses"].append(addr.attrib)
                
                # Parse hostnames
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        host_data["hostnames"].append(hostname.attrib)
                
                # Parse ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "id": port.attrib,
                            "state": port.find("state").attrib if port.find("state") is not None else {},
                            "service": port.find("service").attrib if port.find("service") is not None else {},
                            "scripts": []
                        }
                        
                        # Parse scripts
                        for script in port.findall("script"):
                            script_data = {
                                "id": script.attrib.get("id", ""),
                                "output": script.attrib.get("output", "")
                            }
                            port_data["scripts"].append(script_data)
                        
                        host_data["ports"].append(port_data)
                
                # Parse OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    host_data["os"] = {
                        "matches": [match.attrib for match in os_elem.findall("osmatch")]
                    }
                
                results["hosts"].append(host_data)
            
            return results
        
        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML output: {str(e)}")
            return {"error": f"XML parsing error: {str(e)}"}
    
    def extract_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract open ports from scan results.
        
        Args:
            scan_results: Nmap scan results
            
        Returns:
            list: List of open ports with service information
        """
        open_ports = []
        
        for host in scan_results.get("hosts", []):
            for port in host.get("ports", []):
                # Check if the port is open
                if port.get("state", {}).get("state") == "open":
                    port_info = {
                        "port": port["id"].get("portid"),
                        "protocol": port["id"].get("protocol"),
                        "service": port.get("service", {}).get("name", "unknown"),
                        "version": port.get("service", {}).get("product", ""),
                    }
                    open_ports.append(port_info)
        
        return open_ports
    
    def extract_hosts(self, scan_results: Dict[str, Any]) -> List[str]:
        """
        Extract hosts from scan results.
        
        Args:
            scan_results: Nmap scan results
            
        Returns:
            list: List of host IP addresses
        """
        hosts = []
        
        for host in scan_results.get("hosts", []):
            for addr in host.get("addresses", []):
                if addr.get("addrtype") == "ipv4":
                    hosts.append(addr.get("addr"))
        
        return hosts
    
    def quick_scan(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Run a quick nmap scan to check if a target is up.
        
        Args:
            target: The target to scan
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Scan results
        """
        return self.scan(target, arguments="-sn", timeout=timeout)
    
    def service_scan(self, target: str, ports: str = "1-1000", timeout: int = 300) -> Dict[str, Any]:
        """
        Run a service detection scan.
        
        Args:
            target: The target to scan
            ports: The ports to scan
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Scan results
        """
        return self.scan(target, ports=ports, arguments="-sV -sC", timeout=timeout)
    
    def vulnerability_scan(self, target: str, ports: str = None, timeout: int = 600) -> Dict[str, Any]:
        """
        Run a vulnerability scan using NSE scripts.
        
        Args:
            target: The target to scan
            ports: The ports to scan
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Scan results
        """
        return self.scan(
            target, 
            ports=ports,
            arguments="-sV --script=vuln",
            timeout=timeout
        )