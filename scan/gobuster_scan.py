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

    def __init__(self, binary_path: str = "gobuster", sudo: bool = False):
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
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
        if http_method:
            extra_args += f" -m {http_method}"
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            logger.info(f"Prepending http:// to target: {target}")
        
        output_path = None  
        with tempfile.NamedTemporaryFile(prefix="gobuster_scan_", suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name

        try:
            cmd = self._build_command(target, wordlist, extensions, threads, extra_args, output_path, output_format)
            command_str = " ".join(cmd)
            logger.info(f"Executing gobuster scan: {command_str}")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            logger.debug(f"Gobuster stdout: {process.stdout}")
            logger.debug(f"Gobuster stderr: {process.stderr}")
            
            if process.returncode != 0:
                error_msg = f"Gobuster scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            results = None
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                try:
                    with open(output_path, "r") as f:
                        results = json.load(f)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON output from file: {e}")
            else:
                logger.warning(f"Output file empty or missing: {output_path}")
                if process.stdout and process.stdout.strip():
                    try:
                        results = json.loads(process.stdout)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON output from stdout: {e}")
            
            if results is None:
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
