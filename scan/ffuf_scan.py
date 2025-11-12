import subprocess
import tempfile
import os
import logging
import shlex
import json
from typing import Dict, Any, List, Optional, Union
from utils.retry import retry_operation

logger = logging.getLogger(__name__)

class FFUFScanner:

    def __init__(self, binary_path: str = "ffuf", sudo: bool = False):

        self.binary_path = binary_path
        self.sudo = sudo
        self.verify_installation()

    def verify_installation(self):
        cmd = [self.binary_path, "-V"]
        if self.sudo:
            cmd.insert(0, "sudo")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError(
                    f"ffuf verification failed with code {result.returncode}: {result.stderr.strip()}"
                )
            version_info = result.stdout.splitlines()[0]
            logger.info(f"ffuf version: {version_info}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"ffuf installation verification failed: {e}")
            raise RuntimeError(f"ffuf is not installed or accessible: {e}")

    def _build_command(
        self,
        target: str,
        wordlist: str,
        extensions: Optional[str],
        threads: int,
        extra_args: str,
        output_file: str,
        output_format: str = "json"
    ) -> List[str]:
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.binary_path)
        cmd.extend(["-u", target])
        cmd.extend(["-w", wordlist])
        if extensions and not target.rstrip("/").endswith("FUZZ"):
            cmd.extend(["-e", extensions])
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
        output_format: str = "json"
    ) -> Dict[str, Any]:
        if not os.path.exists(wordlist):
            fallback_paths = [
                wordlist,
                "/usr/share/wordlists/gobuster/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/dirb/wordlists/common.txt"
            ]
            fallback_wordlist = None
            for candidate in fallback_paths:
                if os.path.exists(candidate):
                    fallback_wordlist = candidate
                    logger.warning(f"Wordlist {wordlist} not found, using {candidate} instead")
                    break
            if fallback_wordlist:
                wordlist = fallback_wordlist
            else:
                raise RuntimeError(f"Wordlist {wordlist} not found and no fallback available")
        
        with tempfile.NamedTemporaryFile(prefix="ffuf_scan_", suffix=".json", delete=False) as tmp_file:
            output_path = tmp_file.name

        try:
            cmd = self._build_command(target, wordlist, extensions, threads, extra_args, output_path, output_format)
            command_str = " ".join(cmd)
            logger.info(f"Executing ffuf scan: {command_str}")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if process.returncode != 0:
                error_msg = f"ffuf scan failed with code {process.returncode}: {process.stderr}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            with open(output_path, "r") as f:
                results = json.load(f)
            results.update({
                "command": command_str,
                "stdout": process.stdout,
                "stderr": process.stderr,
            })
            return results
        except subprocess.TimeoutExpired:
            logger.error(f"ffuf scan timed out after {timeout} seconds")
            raise RuntimeError(f"Scan timed out after {timeout} seconds")
        finally:
            try:
                os.unlink(output_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {output_path}: {e}")
