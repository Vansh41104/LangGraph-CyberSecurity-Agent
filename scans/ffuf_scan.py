import subprocess
import json
import tempfile
import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class FFUFScanner:
    """
    Wrapper for FFUF web fuzzer.
    """
    
    def __init__(self, binary_path: str = "ffuf", wordlists_dir: str = None):
        """
        Initialize the FFUFScanner.
        
        Args:
            binary_path: Path to the ffuf binary
            wordlists_dir: Directory containing wordlists
        """
        self.binary_path = binary_path
        self.wordlists_dir = wordlists_dir or "/usr/share/wordlists"
        self.verify_installation()
        
    def verify_installation(self):
        """Verify that ffuf is installed and available."""
        try:
            result = subprocess.run(
                [self.binary_path, "-V"],
                capture_output=True,
                text=True,
                timeout=5
            )
            logger.info(f"FFUF version: {result.stdout.strip()}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"FFUF installation verification failed: {str(e)}")
            raise RuntimeError("FFUF is not properly installed or accessible")
    
    def get_wordlist_path(self, wordlist_name: str) -> str:
        """
        Get the full path to a wordlist.
        
        Args:
            wordlist_name: Name of the wordlist
            
        Returns:
            str: Full path to the wordlist
        """
        # Check if wordlist_name is already a full path
        if os.path.isfile(wordlist_name):
            return wordlist_name
        
        # Check if wordlist_name exists in the wordlists directory
        wordlist_path = os.path.join(self.wordlists_dir, wordlist_name)
        if os.path.isfile(wordlist_path):
            return wordlist_path
        
        # Common directories for wordlists in Kali/ParrotOS/etc.
        common_paths = [
            self.wordlists_dir,
            "/usr/share/wordlists",
            "/usr/share/seclists",
            "/usr/share/dirb/wordlists",
            "/usr/share/dirbuster/wordlists"
        ]
        
        # Try to find the wordlist in common directories
        for directory in common_paths:
            # Check for direct file match
            path = os.path.join(directory, wordlist_name)
            if os.path.isfile(path):
                return path
            
            # Check for file with .txt extension
            path_txt = f"{path}.txt"
            if os.path.isfile(path_txt):
                return path_txt
        
        # Fall back to a common wordlist if the specified one wasn't found
        fallback_wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        for fallback in fallback_wordlists:
            if os.path.isfile(fallback):
                logger.warning(f"Wordlist '{wordlist_name}' not found, using fallback: {fallback}")
                return fallback
        
        # If we get here, we couldn't find any suitable wordlist
        raise FileNotFoundError(f"Wordlist '{wordlist_name}' not found")
    
    @retry_operation(max_retries=2)
    def fuzz(
        self,
        target: str,
        wordlist: str = "dirb/common.txt",
        method: str = "GET",
        extensions: str = None,
        threads: int = 40,
        timeout: int = 300,
        additional_args: str = "",
        filter_codes: str = None,
        filter_size: str = None,
        filter_words: str = None,
        filter_lines: str = None,
        recursive: bool = False,
    ) -> Dict[str, Any]:
        """
        Run a fuzzing scan against a target.
        
        Args:
            target: The target URL to scan (must contain FUZZ keyword)
            wordlist: Path to the wordlist or name of a common wordlist
            method: HTTP method (GET, POST, etc.)
            extensions: File extensions to use (comma-separated)
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            additional_args: Additional ffuf arguments
            filter_codes: HTTP status codes to filter (comma-separated)
            filter_size: Response sizes to filter (comma-separated)
            filter_words: Word counts to filter (comma-separated)
            filter_lines: Line counts to filter (comma-separated)
            recursive: Whether to scan recursively
            
        Returns:
            dict: Parsed scan results
        """
        # Ensure target has correct format (http:// or https://)
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        
        # Ensure the FUZZ keyword is present
        if "FUZZ" not in target:
            # Append FUZZ to the URL path
            if target.endswith("/"):
                target = f"{target}FUZZ"
            else:
                target = f"{target}/FUZZ"
        
        # Get the full path to the wordlist
        wordlist_path = self.get_wordlist_path(wordlist)
        
        # Create a temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name
        
        try:
            # Build the ffuf command
            cmd = [
                self.binary_path,
                "-u", target,
                "-w", wordlist_path,
                "-o", output_path,
                "-X", method,
                "-t", str(threads),
                "-of", "json"
            ]
            
            # Add extensions if specified
            if extensions:
                cmd.extend(["-e", extensions])
            
            # Add filters if specified
            if filter_codes:
                cmd.extend(["-fc", filter_codes])
            if filter_size:
                cmd.extend(["-fs", filter_size])
            if filter_words:
                cmd.extend(["-fw", filter_words])
            if filter_lines:
                cmd.extend(["-fl", filter_lines])
            
            # Add recursive flag if specified
            if recursive:
                cmd.append("-recursion")
            
            # Add additional arguments
            if additional_args:
                cmd.extend(additional_args.split())
            
            command_str = " ".join(cmd)
            logger.info(f"Executing ffuf scan: {command_str}")
            
            # Execute the scan
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Parse the output
            scan_results = self._parse_output(output_path)
            
            # Add raw command and command output to results
            scan_results["command"] = command_str
            scan_results["stdout"] = process.stdout
            scan_results["stderr"] = process.stderr
            
            return scan_results
        
        finally:
            # Clean up the temporary file
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_output(self, output_file: str) -> Dict[str, Any]:
        """
        Parse ffuf output file.
        
        Args:
            output_file: Path to the output file
            
        Returns:
            dict: Parsed scan results
        """
        try:
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                return {
                    "success": False,
                    "error": "No output file or empty output file",
                    "results": []
                }
            
            with open(output_file, "r") as f:
                # The file should contain JSON data
                data = json.load(f)
                
                # Process the results
                results = []
                for item in data.get("results", []):
                    results.append({
                        "url": item.get("url", ""),
                        "status": item.get("status", 0),
                        "length": item.get("length", 0),
                        "words": item.get("words", 0),
                        "lines": item.get("lines", 0),
                        "content_type": item.get("content-type", ""),
                        "input": item.get("input", {})
                    })
                
                return {
                    "success": True,
                    "results": results,
                    "count": len(results),
                    "scan_info": {
                        "target": data.get("commandline", "").split("-u ")[1].split(" ")[0] if "-u " in data.get("commandline", "") else "",
                        "wordlist": data.get("commandline", "").split("-w ")[1].split(" ")[0] if "-w " in data.get("commandline", "") else "",
                        "time": data.get("time", ""),
                        "date": data.get("date", "")
                    }
                }
        
        except (json.JSONDecodeError, FileNotFoundError, IndexError) as e:
            logger.error(f"Error parsing ffuf output: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to parse output: {str(e)}",
                "results": []
            }
    
    def discover_parameters(
        self,
        target: str,
        wordlist: str = "seclists/Discovery/Web-Content/burp-parameter-names.txt",
        method: str = "GET",
        threads: int = 40,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Discover parameters for a URL.
        
        Args:
            target: The target URL to scan
            wordlist: Path to the wordlist of parameter names
            method: HTTP method (GET, POST, etc.)
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Parsed scan results
        """
        # Format the target URL with the FUZZ placeholder for parameter name
        if "?" not in target:
            target = f"{target}?FUZZ=value"
        else:
            target = f"{target}&FUZZ=value"
        
        return self.fuzz(
            target=target,
            wordlist=wordlist,
            method=method,
            threads=threads,
            timeout=timeout,
            filter_codes="404"  # Filter out 404 responses
        )
    
    def discover_virtual_hosts(
        self,
        target: str,
        domain: str,
        wordlist: str = "seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        threads: int = 40,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Discover virtual hosts for a domain.
        
        Args:
            target: The target URL to scan
            domain: The domain to fuzz subdomains for
            wordlist: Path to the wordlist of subdomain names
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Parsed scan results
        """
        # Ensure target has correct format
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        
        # Extract the host
        host = target.split("://")[1].split("/")[0]
        
        # Format the command for virtual host discovery
        cmd_args = f"-H \"Host: FUZZ.{domain}\" -u {target}"
        
        return self.fuzz(
            target=target,
            wordlist=wordlist,
            additional_args=cmd_args,
            threads=threads,
            timeout=timeout,
            filter_size="0"  # Filter out empty responses
        )
    
    def discover_api_endpoints(
        self,
        target: str,
        wordlist: str = "seclists/Discovery/Web-Content/api-endpoints.txt",
        extensions: str = "json,xml",
        threads: int = 40,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Discover API endpoints for a target.
        
        Args:
            target: The target URL to scan
            wordlist: Path to the wordlist of API endpoint names
            extensions: File extensions to use (comma-separated)
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Parsed scan results
        """
        # Ensure target has correct format
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        
        # Ensure target has /api/ path if not already present
        if "/api/" not in target:
            if target.endswith("/"):
                target = f"{target}api/FUZZ"
            else:
                target = f"{target}/api/FUZZ"
        else:
            # If /api/ is already in the URL, append FUZZ
            if target.endswith("/"):
                target = f"{target}FUZZ"
            else:
                target = f"{target}/FUZZ"
        
        return self.fuzz(
            target=target,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads,
            timeout=timeout,
            recursive=True
        )