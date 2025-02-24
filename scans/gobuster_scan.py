import subprocess
import json
import tempfile
import os
import logging
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class GoBusterScanner:
    """
    Wrapper for gobuster directory scanner.
    """
    
    def __init__(self, binary_path: str = "gobuster", wordlists_dir: str = None):
        """
        Initialize the GoBusterScanner.
        
        Args:
            binary_path: Path to the gobuster binary
            wordlists_dir: Directory containing wordlists
        """
        self.binary_path = binary_path
        self.wordlists_dir = wordlists_dir or "/usr/share/wordlists"
        self.verify_installation()
        
    def verify_installation(self):
        """Verify that gobuster is installed and available."""
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            logger.info(f"GoBuster version: {result.stdout.strip()}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"GoBuster installation verification failed: {str(e)}")
            raise RuntimeError("GoBuster is not properly installed or accessible")
    
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
            
            # Check for directory traversal (e.g., "dirb/common.txt")
            if "/" in wordlist_name:
                parts = wordlist_name.split("/")
                nested_path = os.path.join(directory, *parts)
                if os.path.isfile(nested_path):
                    return nested_path
        
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
    def scan_dirs(
        self,
        target: str,
        wordlist: str = "dirb/common.txt",
        extensions: str = "php,html,txt",
        threads: int = 10,
        timeout: int = 300,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run a directory scan against a target.
        
        Args:
            target: The target URL to scan
            wordlist: Path to the wordlist or name of a common wordlist
            extensions: File extensions to look for
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            additional_args: Additional gobuster arguments
            
        Returns:
            dict: Parsed scan results
        """
        # Ensure target has correct format (http:// or https://)
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"
        
        # Get the full path to the wordlist
        wordlist_path = self.get_wordlist_path(wordlist)
        
        # Create a temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name
        
        try:
            # Build the gobuster command
            cmd = [
                self.binary_path,
                "dir",
                "--url", target,
                "--wordlist", wordlist_path,
                "--output", output_path,
                "--threads", str(threads)
            ]
            
            # Add extensions if specified
            if extensions:
                cmd.extend(["--extensions", extensions])
            
            # Add output format
            cmd.extend(["--output-format", "json"])
            
            # Add additional arguments
            if additional_args:
                cmd.extend(additional_args.split())
            
            command_str = " ".join(cmd)
            logger.info(f"Executing gobuster scan: {command_str}")
            
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
        Parse gobuster output file.
        
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
                if isinstance(data, list):
                    for item in data:
                        results.append({
                            "path": item.get("path", ""),
                            "status": item.get("status", 0),
                            "size": item.get("size", 0),
                            "url": item.get("url", "")
                        })
                
                return {
                    "success": True,
                    "results": results,
                    "count": len(results)
                }
        
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error parsing gobuster output: {str(e)}")
            
            # Try to parse the output as text if JSON parsing fails
            try:
                with open(output_file, "r") as f:
                    lines = f.readlines()
                
                results = []
                for line in lines:
                    # Look for URL patterns in the output
                    match = re.search(r"(https?://[^\s]+)", line)
                    if match:
                        url = match.group(1)
                        results.append({
                            "url": url,
                            "path": url.split("/")[-1],
                            "status": 0,  # Status not available
                            "size": 0     # Size not available
                        })
                
                return {
                    "success": True,
                    "results": results,
                    "count": len(results),
                    "note": "Parsed from text output, not all fields available"
                }
            
            except Exception as text_e:
                return {
                    "success": False,
                    "error": f"Failed to parse output: {str(e)}, text parsing also failed: {str(text_e)}",
                    "results": []
                }
    
    def scan_vhosts(
        self,
        target: str,
        wordlist: str = "dirb/common.txt",
        threads: int = 10,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Run a virtual host discovery scan.
        
        Args:
            target: The target domain to scan
            wordlist: Path to the wordlist or name of a common wordlist
            threads: Number of threads to use
            timeout: Timeout for the scan in seconds
            
        Returns:
            dict: Parsed scan results
        """
        # Get the full path to the wordlist
        wordlist_path = self.get_wordlist_path(wordlist)
        
        # Create a temporary file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name
        
        try:
            # Build the gobuster command for vhost mode
            cmd = [
                self.binary_path,
                "vhost",
                "--url", target,
                "--wordlist", wordlist_path,
                "--output", output_path,
                "--threads", str(threads),
                "--output-format", "json"
            ]
            
            command_str = " ".join(cmd)
            logger.info(f"Executing gobuster vhost scan: {command_str}")
            
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