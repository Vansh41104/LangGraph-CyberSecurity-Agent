from typing import Optional, Dict, Any, List
from langchain.tools import BaseTool
from pydantic import Field
import logging

from scan.nmap_scan import NmapScanner
from scan.gobuster_scan import GobusterScanner
from scan.ffuf_scan import FFUFScanner
from scan.sqlmap_scan import SQLMapScanner

logger = logging.getLogger(__name__)


class NmapTool(BaseTool):
    
    name: str = "nmap_scanner"
    description: str = "Performs network mapping and port scanning using Nmap."
    
    scanner: NmapScanner = Field(default_factory=NmapScanner)
    
    def _run(self, target: str, ports: str = "1-1000", arguments: str = "", 
             timeout: int = 180, **kwargs) -> Dict[str, Any]:
        try:
            logger.info(f"Running Nmap scan on {target}")
            result = self.scanner.scan(
                target=target,
                ports=ports,
                arguments=arguments,
                timeout=min(timeout, 300)
            )
            return result
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not supported")


class GobusterTool(BaseTool):
    
    name: str = "gobuster_scanner"
    description: str = "Performs directory and file enumeration on web servers using Gobuster."
    
    scanner: GobusterScanner = Field(default_factory=GobusterScanner)
    
    def _run(self, target: str, wordlist: Optional[str] = None, 
             timeout: int = 180, **kwargs) -> Dict[str, Any]:
        try:
            logger.info(f"Running Gobuster scan on {target}")
            
            if not wordlist:
                default_wordlists = [
                    "/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/wordlists/gobuster/common.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                ]
                for wl in default_wordlists:
                    try:
                        with open(wl, 'r'):
                            wordlist = wl
                            break
                    except FileNotFoundError:
                        continue
                
                if not wordlist:
                    return {"error": "No wordlist found", "status": "failed"}
            
            result = self.scanner.scan(
                target=target,
                wordlist=wordlist,
                timeout=min(timeout, 300)
            )
            return result
        except Exception as e:
            logger.error(f"Gobuster scan failed: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not supported")


class FFUFTool(BaseTool):
    
    name: str = "ffuf_scanner"
    description: str = "Performs web fuzzing to discover hidden endpoints using FFUF."
    
    scanner: FFUFScanner = Field(default_factory=FFUFScanner)
    
    def _run(self, target: str, wordlist: Optional[str] = None,
             timeout: int = 180, **kwargs) -> Dict[str, Any]:
        try:
            logger.info(f"Running FFUF scan on {target}")
            
            if not wordlist:
                default_wordlists = [
                    "/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
                ]
                for wl in default_wordlists:
                    try:
                        with open(wl, 'r'):
                            wordlist = wl
                            break
                    except FileNotFoundError:
                        continue
                
                if not wordlist:
                    return {"error": "No wordlist found", "status": "failed"}
            
            result = self.scanner.scan(
                target=target,
                wordlist=wordlist,
                timeout=min(timeout, 300)
            )
            return result
        except Exception as e:
            logger.error(f"FFUF scan failed: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not supported")


class SQLMapTool(BaseTool):
    
    name: str = "sqlmap_scanner"
    description: str = "Tests for SQL injection vulnerabilities using SQLMap."
    
    scanner: SQLMapScanner = Field(default_factory=SQLMapScanner)
    
    def _run(self, target_url: str, dbs: bool = True, batch: bool = True,
             timeout: int = 300, **kwargs) -> Dict[str, Any]:
        try:
            logger.info(f"Running SQLMap scan on {target_url}")
            
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"http://{target_url}"
            
            result = self.scanner.scan(
                target_url=target_url,
                dbs=dbs,
                batch=batch,
                timeout=min(timeout, 420)
            )
            return result
        except Exception as e:
            logger.error(f"SQLMap scan failed: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    async def _arun(self, *args, **kwargs):
        raise NotImplementedError("Async not supported")


def get_security_tools() -> List[BaseTool]:
    return [
        NmapTool(),
        GobusterTool(),
        FFUFTool(),
        SQLMapTool()
    ]


def get_tool_by_name(tool_name: str) -> Optional[BaseTool]:
    tools_map = {
        "nmap": NmapTool(),
        "gobuster": GobusterTool(),
        "ffuf": FFUFTool(),
        "sqlmap": SQLMapTool()
    }
    return tools_map.get(tool_name.lower())
