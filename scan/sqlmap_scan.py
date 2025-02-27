import subprocess
import tempfile
import os
import logging
import shlex
from typing import Dict, Any, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class SQLMapScanner:
    """
    Wrapper for sqlmap to test for SQL injection vulnerabilities.
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
                    f"SQLMap verification failed with code {result.returncode}: {result.stderr.strip()}"
                )
            version_line = result.stdout.splitlines()[0]
            logger.info(f"SQLMap version: {version_line}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"SQLMap installation verification failed: {e}")
            raise RuntimeError(f"SQLMap is not installed or accessible: {e}")

    @retry_operation(max_retries=2, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError))
    def scan(
        self,
        target_url: str,
        risk: str = "3",
        timeout: int = 300,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Run a sqlmap scan against a target URL.

        Args:
            target_url: The target URL (e.g., "http://example.com/page.php?id=1").
            risk: The risk level (default "3").
            timeout: Timeout for the scan in seconds.
            **kwargs: Additional arguments to pass to sqlmap.

        Returns:
            dict: Parsed scan results.
        """
        with tempfile.NamedTemporaryFile(prefix="sqlmap_scan_", suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name

        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        # Use target_url and include common options
        cmd.extend(["-u", target_url, f"--risk={risk}", "--batch", "--random-agent"])
        # Optionally, add an output directory (here we use the directory of our temp file)
        cmd.extend(["--output-dir", os.path.dirname(output_path)])
        command_str = " ".join(cmd)
        logger.info(f"Executing SQLMap scan: {command_str}")

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if process.returncode != 0:
                error_msg = f"SQLMap scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            # For simplicity, return the raw output as a dictionary.
            result = {
                "command": command_str,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"SQLMap scan timed out after {timeout} seconds")
            raise RuntimeError(f"SQLMap scan timed out after {timeout} seconds")
        finally:
            try:
                os.unlink(output_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {output_path}: {e}")
