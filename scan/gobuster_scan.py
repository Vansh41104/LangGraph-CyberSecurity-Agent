import subprocess
import tempfile
import os
import logging
import shlex
import json
from typing import Dict, Any, List, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class GobusterScanner:
    """
    Wrapper for Gobuster to perform directory and file enumeration.
    """

    def __init__(self, binary_path: str = "gobuster", sudo: bool = False):
        """
        Initialize the GobusterScanner.

        Args:
            binary_path: Path to the gobuster executable.
            sudo: Whether to run gobuster with sudo.
        """
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
        """Verify that gobuster is installed and accessible."""
        cmd = [self.binary_path, "version"]
        if self.sudo:
            cmd.insert(0, "sudo")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError(
                    f"Gobuster verification failed with code {result.returncode}: {result.stderr.strip()}"
                )
            version_info = result.stdout.splitlines()[0]
            logger.info(f"Gobuster version: {version_info}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Gobuster installation verification failed: {e}")
            raise RuntimeError(f"Gobuster is not installed or accessible: {e}")

    def _build_command(
        self,
        target: str,
        wordlist: str,
        extensions: Optional[str],
        threads: int,
        extra_args: str,
        output_file: str,
        output_format: str = "json",
    ) -> List[str]:
        """
        Build the gobuster command.

        Args:
            target: URL target (e.g., http://example.com).
            wordlist: Path to the wordlist.
            extensions: Comma-separated list of file extensions (optional).
            threads: Number of threads to use.
            extra_args: Any additional arguments.
            output_file: Path to output file.
            output_format: Format of output (default: json).

        Returns:
            List of command elements.
        """
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        cmd.append("dir")
        cmd.extend(["-u", target])
        cmd.extend(["-w", wordlist])
        if extensions:
            cmd.extend(["-x", extensions])
        cmd.extend(["-t", str(threads)])
        cmd.extend(["-of", output_format, "-o", output_file])
        if extra_args:
            cmd.extend(shlex.split(extra_args))
        return cmd

    @retry_operation(max_retries=2, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError))
    def scan(
        self,
        target: str,
        wordlist: str,
        extensions: Optional[str] = None,
        threads: int = 10,
        extra_args: str = "",
        timeout: int = 300,
        output_format: str = "json",
        http_method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a gobuster scan against the target.
        
        Args:
            target: The URL target.
            wordlist: Path to wordlist file.
            extensions: Comma-separated file extensions.
            threads: Number of threads.
            extra_args: Additional gobuster arguments.
            timeout: Timeout in seconds.
            output_format: Format for output, defaults to json.
            http_method: HTTP method to use (GET, POST, etc.)

        Returns:
            Parsed scan results as dictionary.
        """
        # Add http_method to extra_args if provided
        if http_method:
            extra_args += f" -m {http_method}"
        
        # Ensure the target URL is properly formatted with http:// or https://
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            logger.info(f"Prepending http:// to target: {target}")
        
        output_path = None  # Initialize before the with block.
        with tempfile.NamedTemporaryFile(prefix="gobuster_scan_", suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name

        try:
            cmd = self._build_command(target, wordlist, extensions, threads, extra_args, output_path, output_format)
            command_str = " ".join(cmd)
            logger.info(f"Executing gobuster scan: {command_str}")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            # Always log stdout and stderr regardless of return code
            logger.debug(f"Gobuster stdout: {process.stdout}")
            logger.debug(f"Gobuster stderr: {process.stderr}")
            
            if process.returncode != 0:
                error_msg = f"Gobuster scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            results = None
            # Check if output file exists and has content
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                try:
                    with open(output_path, "r") as f:
                        results = json.load(f)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON output from file: {e}")
            else:
                logger.warning(f"Output file empty or missing: {output_path}")
                # Fallback: attempt to parse stdout if available
                if process.stdout and process.stdout.strip():
                    try:
                        results = json.loads(process.stdout)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON output from stdout: {e}")
            
            if results is None:
                # If still no valid JSON, return an empty results structure
                results = {
                    "results": [],
                    "error": "Empty or missing output file",
                    "raw_stdout": process.stdout,
                    "raw_stderr": process.stderr
                }
            
            results.update({
                "command": command_str,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "target": target,
                "wordlist": wordlist
            })
            return results
        except subprocess.TimeoutExpired:
            logger.error(f"Gobuster scan timed out after {timeout} seconds")
            raise RuntimeError(f"Scan timed out after {timeout} seconds")
        finally:
            if output_path is not None:
                try:
                    os.unlink(output_path)
                except Exception as e:
                    logger.warning(f"Failed to remove temporary file {output_path}: {e}")
