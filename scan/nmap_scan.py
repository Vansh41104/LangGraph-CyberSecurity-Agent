import subprocess
import tempfile
import os
import logging
import shlex
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class NmapScanner:

    def __init__(self, binary_path: str = "nmap", sudo: bool = False):
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
        """Verify that nmap is installed and accessible."""
        cmd = [self.binary_path, "--version"]
        if self.sudo:
            cmd.insert(0, "sudo")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Nmap verification failed with code {result.returncode}: {result.stderr.strip()}"
                )
            version_line = result.stdout.splitlines()[0]
            logger.info(f"Nmap version: {version_line}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap installation verification failed: {e}")
            raise RuntimeError(f"Nmap is not installed or accessible: {e}")

    def _build_command(
        self,
        target: Union[str, List[str]],
        ports: Optional[str],
        arguments: str,
        xml_output_path: str,
    ) -> List[str]:
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        cmd.extend(["-oX", xml_output_path])
        if ports:
            cmd.extend(["-p", ports])
        if arguments:
            cmd.extend(shlex.split(arguments))
        if isinstance(target, list):
            cmd.extend(target)
        else:
            cmd.append(target)
        return cmd

    @retry_operation(
        max_retries=2, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError)
    )
    def scan(
        self,
        target: Union[str, List[str]],
        ports: Optional[str] = None,
        arguments: str = "-sV -sC",
        command: Optional[str] = None,
        timeout: int = 300,
        scan_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not target:
            logger.error("No target specified for nmap scan")
            raise ValueError("No target specified for nmap scan")
        if scan_type:
            arguments = self._get_arguments_for_scan_type(scan_type, arguments)
        if command is not None:
            arguments = command

        with tempfile.NamedTemporaryFile(prefix="nmap_scan_", suffix=".xml", delete=False) as tmp_file:
            xml_output_path = tmp_file.name

        try:
            logger.debug(f"Building nmap command for target: {target}")
            cmd = self._build_command(target, ports, arguments, xml_output_path)
            command_str = " ".join(cmd)
            logger.info(f"Executing nmap scan: {command_str}")

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if process.returncode != 0:
                error_msg = f"Nmap scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            scan_results = self._parse_xml_output(xml_output_path)
            scan_results.update({
                "command": command_str,
                "stdout": process.stdout,
                "stderr": process.stderr,
            })
            return scan_results

        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out after {timeout} seconds")
            raise RuntimeError(f"Scan timed out after {timeout} seconds")
        finally:
            try:
                os.unlink(xml_output_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {xml_output_path}: {e}")

    def _get_arguments_for_scan_type(self, scan_type: str, default_args: str) -> str:
        scan_types = {
            "quick": "-sn",
            "ping": "-sn",
            "service": "-sV -sC",
            "version": "-sV",
            "script": "-sC",
            "full": "-sS -sV -sC -O",
            "comprehensive": "-sS -sV -sC -O -A",
            "vulnerability": "-sV --script=vuln",
            "ssh_vulnerability": "-sV --script=ssh-*",
            "udp": "-sU",
            "stealth": "-sS",
            "tcp_connect": "-sT",
            "os_detection": "-O",
        }
        return scan_types.get(scan_type.lower(), default_args)

    def _parse_xml_output(self, xml_file: str) -> Dict[str, Any]:
        if not os.path.exists(xml_file):
            logger.error(f"XML output file not found: {xml_file}")
            return {"error": "XML output file not found"}
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing XML: {e}")
            with open(xml_file, "r") as f:
                partial_content = f.read()[:500]
            return {"error": f"XML parsing error: {e}", "partial_content": partial_content}
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {e}")
            return {"error": f"Parsing error: {e}"}

        results = {
            "scan_info": root.find("scaninfo").attrib if root.find("scaninfo") is not None else {},
            "hosts": [],
            "runtime": {},
            "stats": {},
        }
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                results["runtime"] = finished.attrib
            hosts_stats = runstats.find("hosts")
            if hosts_stats is not None:
                results["stats"]["hosts"] = hosts_stats.attrib

        for host in root.findall("host"):
            host_data = {
                "status": host.find("status").attrib if host.find("status") is not None else {},
                "addresses": [addr.attrib for addr in host.findall("address")],
                "hostnames": ([hn.attrib for hn in host.find("hostnames").findall("hostname")]
                              if host.find("hostnames") is not None else []),
                "ports": [],
                "scripts": [],
            }
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for extraports in ports_elem.findall("extraports"):
                    host_data.setdefault("extraports", []).append(extraports.attrib)
                for port in ports_elem.findall("port"):
                    port_data = {
                        "id": port.attrib.get("portid", "unknown"),
                        "protocol": port.attrib.get("protocol", "unknown"),
                        "state": port.find("state").attrib if port.find("state") is not None else {},
                        "service": port.find("service").attrib if port.find("service") is not None else {},
                        "scripts": [],
                    }
                    for script in port.findall("script"):
                        script_data = {
                            "id": script.attrib.get("id", ""),
                            "output": script.attrib.get("output", ""),
                            "elements": {}
                        }
                        for table in script.findall("table"):
                            key = table.attrib.get("key", f"table_{len(script_data['elements'])}")
                            script_data["elements"][key] = self._parse_script_table(table)
                        port_data["scripts"].append(script_data)
                    host_data["ports"].append(port_data)
            hostscript_elem = host.find("hostscript")
            if hostscript_elem is not None:
                for script in hostscript_elem.findall("script"):
                    script_data = {
                        "id": script.attrib.get("id", ""),
                        "output": script.attrib.get("output", ""),
                        "elements": {}
                    }
                    for table in script.findall("table"):
                        key = table.attrib.get("key", f"table_{len(script_data['elements'])}")
                        script_data["elements"][key] = self._parse_script_table(table)
                    host_data["scripts"].append(script_data)
            os_elem = host.find("os")
            if os_elem is not None:
                host_data["os"] = {
                    "matches": [match.attrib for match in os_elem.findall("osmatch")],
                    "classes": [cls.attrib for cls in os_elem.findall("osclass")],
                }
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

    def _parse_script_table(self, table_elem: ET.Element) -> Union[Dict[str, Any], List[Any]]:
        if "key" in table_elem.attrib:
            result = {}
            for elem in table_elem:
                if elem.tag == "elem":
                    result[elem.attrib.get("key", "")] = elem.text
                elif elem.tag == "table":
                    key = elem.attrib.get("key", f"table_{len(result)}")
                    result[key] = self._parse_script_table(elem)
            return result
        else:
            result = []
            for elem in table_elem:
                if elem.tag == "elem":
                    result.append(elem.text)
                elif elem.tag == "table":
                    result.append(self._parse_script_table(elem))
            return result

    def extract_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        open_ports = []
        for host in scan_results.get("hosts", []):
            ip = next((addr.get("addr") for addr in host.get("addresses", [])
                       if addr.get("addrtype") == "ipv4"), None)
            hostname = next((h.get("name") for h in host.get("hostnames", []) if h.get("name")), None)
            for port in host.get("ports", []):
                state = port.get("state", {}).get("state")
                if state == "open":
                    port_number = port.get("id")
                    protocol = port.get("protocol")
                    service_data = port.get("service", {})
                    port_info = {
                        "host_ip": ip,
                        "hostname": hostname,
                        "port": port_number,
                        "protocol": protocol,
                        "service": service_data.get("name", "unknown"),
                        "product": service_data.get("product", ""),
                        "version": service_data.get("version", ""),
                        "extrainfo": service_data.get("extrainfo", ""),
                        "tunnel": service_data.get("tunnel", ""),
                        "cpe": service_data.get("cpe", ""),
                        "scripts": [script.get("id") for script in port.get("scripts", [])],
                    }
                    open_ports.append(port_info)
        return open_ports

    def extract_hosts(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        hosts = []
        for host in scan_results.get("hosts", []):
            host_info = {
                "status": host.get("status", {}).get("state", "unknown"),
                "addresses": {addr.get("addrtype"): addr.get("addr") for addr in host.get("addresses", [])},
                "hostnames": [{"name": h.get("name"), "type": h.get("type", "")}
                              for h in host.get("hostnames", []) if h.get("name")],
                "open_ports_count": sum(1 for port in host.get("ports", [])
                                         if port.get("state", {}).get("state") == "open"),
            }
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
        return self.scan(target, arguments="-sn", timeout=timeout, scan_type="quick")

    def service_scan(self, target: Union[str, List[str]], ports: str = "1-1000", timeout: int = 300) -> Dict[str, Any]:
        return self.scan(target, ports=ports, scan_type="service", timeout=timeout)

    def vulnerability_scan(self, target: Union[str, List[str]], ports: Optional[str] = None, timeout: int = 600) -> Dict[str, Any]:
        return self.scan(target, ports=ports, scan_type="vulnerability", timeout=timeout)

    def stealth_scan(self, target: Union[str, List[str]], ports: str = "1-1000", timeout: int = 300) -> Dict[str, Any]:
        return self.scan(target, ports=ports, scan_type="stealth", timeout=timeout)

    def comprehensive_scan(self, target: Union[str, List[str]], ports: Optional[str] = None, timeout: int = 900) -> Dict[str, Any]:
        return self.scan(target, ports=ports, scan_type="comprehensive", timeout=timeout)

    def get_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        summary = {
            "hosts": {"total": len(scan_results.get("hosts", [])), "up": 0, "down": 0},
            "ports": {"total": 0, "open": 0, "closed": 0, "filtered": 0},
            "services": {},
            "top_ports": [],
        }
        hosts = scan_results.get("hosts", [])
        for host in hosts:
            if host.get("status", {}).get("state") == "up":
                summary["hosts"]["up"] += 1
            else:
                summary["hosts"]["down"] += 1
            for port in host.get("ports", []):
                summary["ports"]["total"] += 1
                state = port.get("state", {}).get("state", "unknown")
                summary["ports"][state] = summary["ports"].get(state, 0) + 1
                if state == "open":
                    service = port.get("service", {}).get("name", "unknown")
                    summary["services"][service] = summary["services"].get(service, 0) + 1

        port_count = {}
        for port_info in self.extract_open_ports(scan_results):
            port = port_info["port"]
            port_count[port] = port_count.get(port, 0) + 1
        top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]
        summary["top_ports"] = [{"port": p, "count": count} for p, count in top_ports]
        return summary
