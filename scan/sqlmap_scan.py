import subprocess
import tempfile
import os
import logging
import shlex
import json
from typing import Dict, Any, List, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class SQLMapScanner:
    """
    Wrapper for sqlmap to test for SQL injection vulnerabilities and extract data.
    """

    def __init__(self, binary_path: str = "sqlmap", sudo: bool = False):
        """
        Initialize the SQLMapScanner.

        Args:
            binary_path: Path to the sqlmap executable.
            sudo: Whether to run sqlmap with sudo.
        """
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
        """Verify that sqlmap is installed and accessible."""
        cmd = [self.binary_path, "--version"]
        if self.sudo:
            cmd.insert(0, "sudo")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError(
                    f"sqlmap verification failed with code {result.returncode}: {result.stderr.strip()}"
                )
            version_info = result.stdout.splitlines()[0]
            logger.info(f"sqlmap version: {version_info}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"sqlmap installation verification failed: {e}")
            raise RuntimeError(f"sqlmap is not installed or accessible: {e}")

    def _build_command(
        self,
        target_url: str,
        extra_args: str,
        output_dir: str
    ) -> List[str]:
        """
        Build the sqlmap command.

        Args:
            target_url: The URL to test.
            extra_args: Additional sqlmap arguments.
            output_dir: Directory to save sqlmap outputs.

        Returns:
            List of command elements.
        """
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        cmd.extend(["-u", target_url, "--batch", "--dump-all", "--output-dir", output_dir])
        if extra_args:
            cmd.extend(shlex.split(extra_args))
        return cmd

    @retry_operation(max_retries=1, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError))
    def scan(
        self,
        target_url: str,
        extra_args: str = "",
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Run a sqlmap scan against a target URL.

        Args:
            target_url: The URL to test for SQL injection.
            extra_args: Additional sqlmap arguments.
            timeout: Timeout in seconds.

        Returns:
            Dictionary with scan results (text output and metadata).
        """
        with tempfile.TemporaryDirectory(prefix="sqlmap_output_") as output_dir:
            try:
                cmd = self._build_command(target_url, extra_args, output_dir)
                command_str = " ".join(cmd)
                logger.info(f"Executing sqlmap scan: {command_str}")
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if process.returncode != 0:
                    error_msg = f"sqlmap scan failed with code {process.returncode}: {process.stderr}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                # Since sqlmap output is mostly file based, we return the captured stdout along with output directory details.
                results = {
                    "command": command_str,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "output_dir": output_dir
                }
                return results
            except subprocess.TimeoutExpired:
                logger.error(f"sqlmap scan timed out after {timeout} seconds")
                raise RuntimeError(f"Scan timed out after {timeout} seconds")
