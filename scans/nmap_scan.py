import subprocess
import tempfile
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class NmapScanner:
    """
    Wrapper for nmap security scanner.
    """
    
    def __init__(self, binary_path: str = "nmap"):
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
            version_line = result.stdout.split('\n')[0]
            logger.info(f"Nmap version: {version_line}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap installation verification failed: {str(e)}")
            raise RuntimeError("Nmap is not properly installed or accessible")
    
    @retry_operation(max_retries=2)
    def scan(
        self,
        target: str,
        ports: str = None,
        arguments: str = "-sV -sC",
        command: Optional[str] = None,
        timeout: int = 300,
        scan_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run an nmap scan against a target.

        Args:
            target: The target to scan (IP or domain)
            ports: The ports to scan (e.g., "22,80,443" or "1-1000")
            arguments: Additional nmap arguments (default: "-sV -sC")
            command: Alternate scan command to use (overrides arguments if provided)
            timeout: Timeout for the scan in seconds
            scan_type: Type of scan to perform (e.g., "quick", "service", "vulnerability")

        Returns:
            dict: Parsed scan results
        """
        # If a command is provided, override the default arguments.
        if command is not None:
            arguments = command

        # Create a temporary file for XML output.
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_file:
            xml_output_path = tmp_file.name
        
        try:
            # Build the nmap command.
            cmd = [self.binary_path, "-oX", xml_output_path]
            if ports:
                cmd.extend(["-p", ports])
            if arguments:
                cmd.extend(arguments.split())
            cmd.append(target)
            
            command_str = " ".join(cmd)
            logger.info(f"Executing nmap scan: {command_str}")
            
            # Execute the scan.
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Check for errors.
            if process.returncode != 0:
                error_msg = f"Nmap scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Read and log raw XML output for debugging.
            if os.path.exists(xml_output_path):
                with open(xml_output_path, "r") as f:
                    xml_content = f.read().strip()
                logger.debug(f"Raw Nmap XML Output:\n{xml_content}")
            else:
                logger.error("XML output file not found.")
                xml_content = ""
            
            # Parse the XML output.
            scan_results = self._parse_xml_output(xml_output_path)
            scan_results["command"] = command_str
            scan_results["stdout"] = process.stdout
            scan_results["stderr"] = process.stderr
            
            return scan_results
        
        finally:
            # Clean up the temporary file.
            if os.path.exists(xml_output_path):
                os.unlink(xml_output_path)
    
    def _parse_xml_output(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse nmap XML output file.
        """
        try:
            with open(xml_file, 'r') as f:
                xml_content = f.read().strip()
            if not xml_content:
                logger.error("XML output is empty.")
                return {"error": "Empty XML output"}
            
            logger.debug(f"XML content to parse:\n{xml_content}")
            # Parse the XML from the string content.
            root = ET.fromstring(xml_content)
            
            results = {
                "scan_info": {},
                "hosts": []
            }
            
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                results["scan_info"] = scaninfo.attrib
            
            for host in root.findall("host"):
                host_data = {
                    "status": host.find("status").attrib if host.find("status") is not None else {},
                    "addresses": [],
                    "hostnames": [],
                    "ports": []
                }
                
                for addr in host.findall("address"):
                    host_data["addresses"].append(addr.attrib)
                
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        host_data["hostnames"].append(hostname.attrib)
                
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "id": port.attrib,
                            "state": port.find("state").attrib if port.find("state") is not None else {},
                            "service": port.find("service").attrib if port.find("service") is not None else {},
                            "scripts": []
                        }
                        
                        for script in port.findall("script"):
                            script_data = {
                                "id": script.attrib.get("id", ""),
                                "output": script.attrib.get("output", "")
                            }
                            port_data["scripts"].append(script_data)
                        
                        host_data["ports"].append(port_data)
                
                os_elem = host.find("os")
                if os_elem is not None:
                    host_data["os"] = {
                        "matches": [match.attrib for match in os_elem.findall("osmatch")]
                    }
                
                results["hosts"].append(host_data)
            
            if not results["hosts"]:
                logger.warning("No hosts found in nmap XML output.")
            
            return results
        
        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML output: {str(e)}")
            return {"error": f"XML parsing error: {str(e)}"}
    
    def extract_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract open ports from scan results.
        """
        open_ports = []
        for host in scan_results.get("hosts", []):
            for port in host.get("ports", []):
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
        """
        hosts = []
        for host in scan_results.get("hosts", []):
            for addr in host.get("addresses", []):
                if addr.get("addrtype") == "ipv4":
                    hosts.append(addr.get("addr"))
        return hosts
    
    def quick_scan(self, target: str, timeout: int = 60) -> Dict[str, Any]:
        """Run a quick nmap scan to check if a target is up."""
        return self.scan(target, arguments="-sn", timeout=timeout)
    
    def service_scan(self, target: str, ports: str = "1-1000", timeout: int = 300) -> Dict[str, Any]:
        """Run a service detection scan."""
        return self.scan(target, ports=ports, arguments="-sV -sC", timeout=timeout)
    
    def vulnerability_scan(self, target: str, ports: str = None, timeout: int = 600) -> Dict[str, Any]:
        """Run a vulnerability scan using NSE scripts."""
        return self.scan(target, ports=ports, arguments="-sV --script=vuln", timeout=timeout)
