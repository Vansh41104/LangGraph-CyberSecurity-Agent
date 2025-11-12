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

    def __init__(self, binary_path: str = "sqlmap", sudo: bool = False):
        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
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
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"http://{target_url}"
            
        cmd.extend(["-u", target_url, "--batch", "--output-dir", output_dir])
        
        if extra_args:
            cmd.extend(shlex.split(extra_args))
        return cmd

    @retry_operation(max_retries=2, retry_exceptions=(subprocess.TimeoutExpired, RuntimeError))
    def scan(
        self,
        target_url: str,
        extra_args: str = "",
        timeout: int = 600,
        **kwargs
    ) -> Dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="sqlmap_output_") as output_dir:
            try:
                additional_args = []
                flag_options = ["dbs", "batch", "dump-all", "forms", "tables", "columns", "current-user", "current-db"]
                
                for key, value in kwargs.items():
                    if value is not None:
                        if key in flag_options:
                            if value is True or value == 'all':
                                additional_args.append(f"--{key}")
                            additional_args.append(f"--{key}={value}")
                
                if additional_args:
                    if extra_args:
                        extra_args += " " + " ".join(additional_args)
                    else:
                        extra_args = " ".join(additional_args)
                
                cmd = self._build_command(target_url, extra_args, output_dir)
                command_str = " ".join(cmd)
                logger.info(f"Executing sqlmap scan: {command_str}")
                
                logger.debug(f"Current working directory: {os.getcwd()}")
                logger.debug(f"Output directory exists: {os.path.exists(output_dir)}")
                
                # First try with a simpler command to test connectivity
                test_cmd = [self.binary_path, "-u", target_url, "--batch", "--timeout", "30"]
                if self.sudo:
                    test_cmd.insert(0, "sudo")
                
                logger.info(f"Testing target connectivity: {' '.join(test_cmd)}")
                try:
                    test_process = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
                    if test_process.returncode != 0:
                        logger.warning(f"Initial connectivity test failed: {test_process.stderr}")
                    else:
                        logger.info("Target connectivity test successful")
                except Exception as e:
                    logger.warning(f"Target connectivity test failed: {e}")
                
                # Now run the full command
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                
                # Always log the stdout and stderr output for debugging purposes
                if process.stdout:
                    logger.debug(f"SQLMap stdout output: {process.stdout[:1000]}...")
                if process.stderr:
                    logger.debug(f"SQLMap stderr output: {process.stderr}")
                
                if process.returncode != 0:
                    error_msg = f"sqlmap scan failed with code {process.returncode}"
                    if process.stderr:
                        error_msg += f": {process.stderr}"
                    else:
                        error_msg += f" (No error output). Stdout: {process.stdout[:500]}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                
                # Since sqlmap output is mostly file based, we return the captured stdout along with output directory details.
                results = {
                    "command": command_str,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "output_dir": output_dir,
                    "exit_code": process.returncode
                }
                
                # Try to parse and extract key findings from output directory
                try:
                    target_domain = target_url.replace("http://", "").replace("https://", "").split("/")[0]
                    target_dir = os.path.join(output_dir, target_domain)
                    session_path = os.path.join(target_dir, "session.sqlite")
                    logs_path = os.path.join(target_dir, "log")
                    
                    # Ensure the target directory exists
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir, exist_ok=True)
                    
                    # Ensure the log directory exists; if not, create it
                    if not os.path.exists(logs_path):
                        os.makedirs(logs_path, exist_ok=True)
                    
                    if os.path.isdir(logs_path):
                        log_files = os.listdir(logs_path)
                        if log_files:
                            with open(os.path.join(logs_path, log_files[0]), 'r') as f:
                                results["log_content"] = f.read()
                    
                    # List output directory contents for debugging
                    output_files = []
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            output_files.append(os.path.join(root, file))
                    results["output_files"] = output_files
                    logger.debug(f"SQLMap output files: {output_files}")
                except Exception as e:
                    logger.warning(f"Failed to extract additional information from output: {e}")
                
                return results
            except subprocess.TimeoutExpired as e:
                logger.error(f"sqlmap scan timed out after {timeout} seconds")
                raise RuntimeError(f"Scan timed out after {timeout} seconds: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in sqlmap scan: {str(e)}")
                raise RuntimeError(f"SQLMap scan failed: {str(e)}")
