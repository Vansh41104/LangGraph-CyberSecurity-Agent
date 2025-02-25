import subprocess
import tempfile
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    Wrapper for nmap security scanner with enhanced error handling and result parsing.
    """

    def __init__(self, binary_path: str = "nmap", sudo: bool = False):
        """
        Initialize the NmapScanner.

        Args:
            binary_path: Path to the nmap executable
            sudo: Whether to run nmap with sudo for privileged operations
        """
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
        """Verify that nmap is installed and available."""
        try:
            cmd = [self.binary_path, "--version"]
            if self.sudo:
                cmd = ["sudo"] + cmd

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Nmap verification failed with code {result.returncode}: {result.stderr}"
                )

            version_line = result.stdout.split("\n")[0]
            logger.info(f"Nmap version: {version_line}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap installation verification failed: {str(e)}")
            raise RuntimeError(
                f"Nmap is not properly installed or accessible: {str(e)}"
            )

    def _build_command(
        self,
        target: str,
        ports: Optional[str],
        arguments: str,
        xml_output_path: str,
    ) -> List[str]:
        """
        Build the nmap command with appropriate arguments.

        Args:
            target: Target to scan
            ports: Ports to scan
            arguments: Additional nmap arguments
            xml_output_path: Path to save XML output

        Returns:
            List of command elements
        """
        cmd = []
        if self.sudo:
            cmd.append("sudo")

        cmd.append(self.binary_path)
        cmd.extend(["-oX", xml_output_path])

        if ports:
            cmd.extend(["-p", ports])

        # Split arguments properly, handling quoted sections
        if arguments:
            import shlex

            cmd.extend(shlex.split(arguments))

        # Handle multiple targets (comma-separated or CIDR notation)
        if isinstance(target, list):
            cmd.extend(target)
        else:
            cmd.append(target)

        return cmd

    @retry_operation(
        max_retries=2, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError)
    )
    def scan(self, target: Union[str, List[str]], ports: Optional[str] = None,
             arguments: str = "-sV -sC", command: Optional[str] = None,
             timeout: int = 300, scan_type: Optional[str] = None) -> Dict[str, Any]:
        if not target:
            logger.error("No target specified for nmap scan")
            raise ValueError("No target specified for nmap scan")
        logger.debug(f"scan() received target: {target}")
        """
        Run an nmap scan against a target.

        Args:
            target: The target to scan (IP, domain, CIDR range, or list of targets)
            ports: The ports to scan (e.g., "22,80,443" or "1-1000")
            arguments: Additional nmap arguments (default: "-sV -sC")
            command: Alternate scan command to use (overrides arguments if provided)
            timeout: Timeout for the scan in seconds
            scan_type: Type of scan to perform (e.g., "quick", "service", "vulnerability")

        Returns:
            dict: Parsed scan results
        """

        # If scan_type is provided, adjust the arguments
        if scan_type:
            arguments = self._get_arguments_for_scan_type(scan_type, arguments)

        # If a command is provided, override the default arguments.
        if command is not None:
            arguments = command

        # Create a temporary file for XML output with prefix for easier identification
        with tempfile.NamedTemporaryFile(
            prefix="nmap_scan_", suffix=".xml", delete=False
        ) as tmp_file:
            xml_output_path = tmp_file.name

        try:
            # Build the nmap command
            logger.debug(f"Scanning target: {target}")
            cmd = self._build_command(target, ports, arguments, xml_output_path)
            command_str = " ".join(cmd)
            logger.info(f"Executing nmap scan: {command_str}")

            # Execute the scan
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Check for errors
            if process.returncode != 0:
                error_msg = (
                    f"Nmap scan failed with code {process.returncode}: {process.stderr}"
                )
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            # Read and parse XML output
            scan_results = self._parse_xml_output(xml_output_path)

            # Include command and output details
            scan_results["command"] = command_str
            scan_results["stdout"] = process.stdout
            scan_results["stderr"] = process.stderr

            return scan_results

        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out after {timeout} seconds")
            raise RuntimeError(f"Scan timed out after {timeout} seconds")

        finally:
            # Clean up the temporary file
            if os.path.exists(xml_output_path):
                try:
                    os.unlink(xml_output_path)
                except Exception as e:
                    logger.warning(
                        f"Failed to remove temporary file {xml_output_path}: {str(e)}"
                    )

    def _get_arguments_for_scan_type(self, scan_type: str, default_args: str) -> str:
        """
        Get appropriate arguments for the specified scan type.

        Args:
            scan_type: Type of scan to perform
            default_args: Default arguments to use if scan_type is not recognized

        Returns:
            String of nmap arguments
        """
        scan_types = {
            "quick": "-sn",
            "ping": "-sn",
            "service": "-sV -sC",
            "version": "-sV",
            "script": "-sC",
            "full": "-sS -sV -sC -O",
            "comprehensive": "-sS -sV -sC -O -A",
            "vulnerability": "-sV --script=vuln",
            "udp": "-sU",
            "stealth": "-sS",
            "tcp_connect": "-sT",
            "os_detection": "-O",
        }

        return scan_types.get(scan_type.lower(), default_args)

    def _parse_xml_output(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse nmap XML output file with enhanced error handling.

        Args:
            xml_file: Path to the XML output file

        Returns:
            Dictionary of parsed results
        """
        try:
            # First check if file exists and has content
            if not os.path.exists(xml_file):
                logger.error(f"XML output file not found: {xml_file}")
                return {"error": "XML output file not found"}

            file_size = os.path.getsize(xml_file)
            if file_size == 0:
                logger.error("XML output file is empty")
                return {"error": "Empty XML output file"}

            # Read the XML content
            with open(xml_file, "r") as f:
                xml_content = f.read().strip()

            if not xml_content:
                logger.error("XML output is empty")
                return {"error": "Empty XML content"}

            # Parse the XML
            root = ET.fromstring(xml_content)

            # Initialize results structure
            results = {
                "scan_info": {},
                "hosts": [],
                "runtime": {},
                "stats": {},
            }

            # Parse scan info
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                results["scan_info"] = scaninfo.attrib

            # Parse runtime information
            runstats = root.find("runstats")
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    results["runtime"] = finished.attrib

                hosts_stats = runstats.find("hosts")
                if hosts_stats is not None:
                    results["stats"]["hosts"] = hosts_stats.attrib

            # Parse host information
            for host in root.findall("host"):
                host_data = {
                    "status": host.find("status").attrib
                    if host.find("status") is not None
                    else {},
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "scripts": [],
                }

                # Parse addresses
                for addr in host.findall("address"):
                    host_data["addresses"].append(addr.attrib)

                # Parse hostnames
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        host_data["hostnames"].append(hostname.attrib)

                # Parse ports and services
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    # First, check for extraports (filtered, closed, etc.)
                    for extraports in ports_elem.findall("extraports"):
                        if "extraports" not in host_data:
                            host_data["extraports"] = []
                        host_data["extraports"].append(extraports.attrib)

                    # Then parse individual ports
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "id": port.attrib,
                            "state": port.find("state").attrib
                            if port.find("state") is not None
                            else {},
                            "service": port.find("service").attrib
                            if port.find("service") is not None
                            else {},
                            "scripts": [],
                        }

                        # Parse script output
                        for script in port.findall("script"):
                            script_data = {
                                "id": script.attrib.get("id", ""),
                                "output": script.attrib.get("output", ""),
                                "elements": {},
                            }

                            # Parse script elements (tables)
                            for table in script.findall("table"):
                                table_data = self._parse_script_table(table)
                                script_data["elements"][
                                    table.attrib.get("key", f"table_{len(script_data['elements'])}")
                                ] = table_data

                            port_data["scripts"].append(script_data)

                        host_data["ports"].append(port_data)

                # Parse host scripts
                hostscript_elem = host.find("hostscript")
                if hostscript_elem is not None:
                    for script in hostscript_elem.findall("script"):
                        script_data = {
                            "id": script.attrib.get("id", ""),
                            "output": script.attrib.get("output", ""),
                            "elements": {},
                        }

                        # Parse script elements
                        for table in script.findall("table"):
                            table_data = self._parse_script_table(table)
                            script_data["elements"][
                                table.attrib.get("key", f"table_{len(script_data['elements'])}")
                            ] = table_data

                        host_data["scripts"].append(script_data)

                # Parse OS detection results
                os_elem = host.find("os")
                if os_elem is not None:
                    host_data["os"] = {
                        "matches": [match.attrib for match in os_elem.findall("osmatch")],
                        "classes": [cls.attrib for cls in os_elem.findall("osclass")],
                    }

                # Parse trace route if available
                trace = host.find("trace")
                if trace is not None:
                    host_data["trace"] = {
                        "proto": trace.attrib.get("proto", ""),
                        "port": trace.attrib.get("port", ""),
                        "hops": [hop.attrib for hop in trace.findall("hop")],
                    }

                results["hosts"].append(host_data)

            if not results["hosts"]:
                logger.warning("No hosts found in nmap XML output")

            return results

        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML output: {str(e)}")
            # Try to return partial content if available
            with open(xml_file, "r") as f:
                partial_content = f.read()[:500]  # Show first 500 chars for debugging
            return {
                "error": f"XML parsing error: {str(e)}",
                "partial_content": partial_content,
            }
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {str(e)}")
            return {"error": f"Parsing error: {str(e)}"}

    def _parse_script_table(self, table_elem):
        """
        Parse a script table element recursively.

        Args:
            table_elem: Table XML element

        Returns:
            Parsed table data as a dictionary or list
        """
        # Check if table has a "key" attribute
        if "key" in table_elem.attrib:
            # This is a named table, return a dictionary
            result = {}

            # Process table elements
            for elem in table_elem:
                if elem.tag == "elem":
                    result[elem.attrib.get("key", "")] = elem.text
                elif elem.tag == "table":
                    result[elem.attrib.get("key", f"table_{len(result)}")] = (
                        self._parse_script_table(elem)
                    )

            return result
        else:
            # This is an unnamed table, return a list
            result = []

            # Process table elements
            for elem in table_elem:
                if elem.tag == "elem":
                    result.append(elem.text)
                elif elem.tag == "table":
                    result.append(self._parse_script_table(elem))

            return result

    def extract_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract open ports from scan results with improved details.

        Args:
            scan_results: Parsed scan results

        Returns:
            List of open ports with details
        """
        open_ports = []
        for host in scan_results.get("hosts", []):
            # Get host information
            host_info = {
                "ip": None,
                "hostname": None,
            }

            # Extract IP address
            for addr in host.get("addresses", []):
                if addr.get("addrtype") == "ipv4":
                    host_info["ip"] = addr.get("addr")
                    break

            # Extract hostname
            for hostname in host.get("hostnames", []):
                if hostname.get("type") == "PTR":
                    host_info["hostname"] = hostname.get("name")
                    break

            # Extract open ports
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") == "open":
                    service = port.get("service", {})
                    scripts = port.get("scripts", [])

                    port_info = {
                        "host_ip": host_info["ip"],
                        "hostname": host_info["hostname"],
                        "port": port["id"].get("portid"),
                        "protocol": port["id"].get("protocol"),
                        "service": service.get("name", "unknown"),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "extrainfo": service.get("extrainfo", ""),
                        "tunnel": service.get("tunnel", ""),
                        "cpe": service.get("cpe", ""),
                        "scripts": [script.get("id") for script in scripts],
                    }
                    open_ports.append(port_info)

        return open_ports

    def extract_hosts(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract hosts with details from scan results.

        Args:
            scan_results: Parsed scan results

        Returns:
            List of hosts with details
        """
        hosts = []
        for host in scan_results.get("hosts", []):
            host_info = {
                "status": host.get("status", {}).get("state", "unknown"),
                "addresses": {},
                "hostnames": [],
                "open_ports_count": 0,
            }

            # Extract addresses
            for addr in host.get("addresses", []):
                addr_type = addr.get("addrtype")
                if addr_type:
                    host_info["addresses"][addr_type] = addr.get("addr")

            # Extract hostnames
            for hostname in host.get("hostnames", []):
                if "name" in hostname:
                    host_info["hostnames"].append(
                        {
                            "name": hostname.get("name"),
                            "type": hostname.get("type", ""),
                        }
                    )

            # Count open ports
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") == "open":
                    host_info["open_ports_count"] += 1

            # Extract OS information if available
            if "os" in host:
                os_matches = host.get("os", {}).get("matches", [])
                if os_matches:
                    top_match = os_matches[0]
                    host_info["os"] = {
                        "name": top_match.get("name", ""),
                        "accuracy": top_match.get("accuracy", ""),
                        "family": top_match.get("osfamily", ""),
                    }

            hosts.append(host_info)

        return hosts

    def quick_scan(self, target: Union[str, List[str]], timeout: int = 60) -> Dict[str, Any]:
        """
        Run a quick nmap scan to check if targets are up.

        Args:
            target: Target(s) to scan
            timeout: Scan timeout in seconds

        Returns:
            Scan results
        """
        return self.scan(target, arguments="-sn", timeout=timeout, scan_type="quick")

    def service_scan(
        self, target: Union[str, List[str]], ports: str = "1-1000", timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Run a service detection scan.

        Args:
            target: Target(s) to scan
            ports: Ports to scan
            timeout: Scan timeout in seconds

        Returns:
            Scan results
        """
        return self.scan(target, ports=ports, scan_type="service", timeout=timeout)

    def vulnerability_scan(
        self, target: Union[str, List[str]], ports: str = None, timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Run a vulnerability scan using NSE scripts.

        Args:
            target: Target(s) to scan
            ports: Ports to scan
            timeout: Scan timeout in seconds

        Returns:
            Scan results
        """
        return self.scan(target, ports=ports, scan_type="vulnerability", timeout=timeout)

    def stealth_scan(
        self, target: Union[str, List[str]], ports: str = "1-1000", timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Run a stealth SYN scan.

        Args:
            target: Target(s) to scan
            ports: Ports to scan
            timeout: Scan timeout in seconds

        Returns:
            Scan results
        """
        return self.scan(target, ports=ports, scan_type="stealth", timeout=timeout)

    def comprehensive_scan(
        self, target: Union[str, List[str]], ports: str = None, timeout: int = 900
    ) -> Dict[str, Any]:
        """
        Run a comprehensive scan including service detection, scripts, and OS detection.

        Args:
            target: Target(s) to scan
            ports: Ports to scan
            timeout: Scan timeout in seconds

        Returns:
            Scan results
        """
        return self.scan(target, ports=ports, scan_type="comprehensive", timeout=timeout)

    def get_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of scan results.

        Args:
            scan_results: Parsed scan results

        Returns:
            Summary of scan results
        """
        summary = {
            "hosts": {
                "total": 0,
                "up": 0,
                "down": 0,
            },
            "ports": {
                "total": 0,
                "open": 0,
                "closed": 0,
                "filtered": 0,
            },
            "services": {},
            "top_ports": [],
        }

        # Count hosts
        hosts = scan_results.get("hosts", [])
        summary["hosts"]["total"] = len(hosts)

        for host in hosts:
            if host.get("status", {}).get("state") == "up":
                summary["hosts"]["up"] += 1
            else:
                summary["hosts"]["down"] += 1

        # Count ports and services
        for host in hosts:
            for port in host.get("ports", []):
                summary["ports"]["total"] += 1

                state = port.get("state", {}).get("state", "unknown")
                if state in summary["ports"]:
                    summary["ports"][state] += 1
                else:
                    summary["ports"][state] = 1

                # Count services
                if state == "open":
                    service = port.get("service", {}).get("name", "unknown")
                    if service in summary["services"]:
                        summary["services"][service] += 1
                    else:
                        summary["services"][service] = 1

        # Get top open ports
        open_ports = self.extract_open_ports(scan_results)
        port_count = {}

        for port_info in open_ports:
            port = port_info["port"]
            if port in port_count:
                port_count[port] += 1
            else:
                port_count[port] = 1

        # Sort by count and get top 10
        top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]
        summary["top_ports"] = [{"port": p[0], "count": p[1]} for p in top_ports]

        return summary
