#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import base64
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import traceback
import threading
from functools import wraps
from typing import Any, Callable, Dict, List, Optional
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout
MAX_COMMAND_TIMEOUT = int(os.environ.get("MAX_COMMAND_TIMEOUT", 3600))

# Scanners like nuclei, semgrep and trufflehog can emit tens of megabytes. That
# output ultimately lands in an LLM context window, so cap it by default and say
# so in the response rather than silently returning a wall of text.
MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_BYTES", 200_000))

app = Flask(__name__)


def _augment_path():
    """
    Put user-local install prefixes on PATH.

    install-tools.sh installs everything it can without root, which means
    ~/.local/bin and the Go bin dir. Those are usually absent from the
    environment of a service started by systemd or over a non-login ssh shell,
    so resolve them here instead of making every endpoint use absolute paths.
    """
    candidates = [
        os.path.expanduser("~/.local/bin"),
        os.environ.get("GOBIN") or "",
        os.path.join(os.environ.get("GOPATH") or os.path.expanduser("~/go"), "bin"),
        "/usr/local/bin",
        "/usr/local/go/bin",
        "/snap/bin",
    ]
    current = os.environ.get("PATH", "").split(os.pathsep)
    added = [c for c in candidates if c and os.path.isdir(c) and c not in current]
    if added:
        os.environ["PATH"] = os.pathsep.join(added + current)
        logger.debug(f"PATH extended with: {', '.join(added)}")


_augment_path()


def resolve_binary(name: str) -> str:
    """Return the resolved path for a tool, or "" when it is not installed."""
    return shutil.which(name) or ""

class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT, stdin_data: Optional[str] = None):
        self.command = command
        self.timeout = timeout
        # Determine if we should use shell mode based on command type
        self.use_shell = isinstance(command, str)
        # None means "no input": stdin is wired to /dev/null so an unexpectedly
        # interactive tool hits EOF instead of blocking until the timeout. Pass a
        # string to drive a tool that reads commands from stdin.
        self.stdin_data = stdin_data
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdin=subprocess.PIPE if self.stdin_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            if self.stdin_data is not None:
                # Inputs here are a few short lines, so a blocking write cannot
                # fill the pipe buffer and deadlock against the reader threads.
                try:
                    self.process.stdin.write(self.stdin_data)
                    self.process.stdin.close()
                except (BrokenPipeError, OSError) as e:
                    logger.warning(f"Could not write stdin to process: {e}")

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def _truncate(text: str, limit: int) -> tuple:
    """Clip text to `limit` bytes, keeping the head. Returns (text, was_truncated)."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    kept = text[:limit]
    note = (
        f"\n\n[... truncated: {len(text) - limit} of {len(text)} characters omitted. "
        f"Re-run with a narrower scope, or raise max_output_bytes, to see the rest.]"
    )
    return kept + note, True


def execute_command(command, timeout: Optional[int] = None,
                    max_output_bytes: Optional[int] = None,
                    stdin_data: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute a command and return the result.

    Args:
        command: The command to execute (list for safe mode, string for shell mode)
        timeout: Per-command timeout in seconds; falls back to COMMAND_TIMEOUT
        max_output_bytes: Cap on returned stdout/stderr; falls back to MAX_OUTPUT_BYTES
        stdin_data: Text to feed the process on stdin; None wires stdin to /dev/null

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    effective_timeout = COMMAND_TIMEOUT if timeout is None else max(1, min(int(timeout), MAX_COMMAND_TIMEOUT))
    limit = MAX_OUTPUT_BYTES if max_output_bytes is None else int(max_output_bytes)

    executor = CommandExecutor(command, timeout=effective_timeout, stdin_data=stdin_data)
    result = executor.execute()

    result["stdout"], stdout_truncated = _truncate(result.get("stdout", ""), limit)
    result["stderr"], stderr_truncated = _truncate(result.get("stderr", ""), limit)
    if stdout_truncated or stderr_truncated:
        result["truncated"] = True

    # Surface the resolved command so callers can reproduce a run by hand.
    result["command"] = command if isinstance(command, str) else " ".join(shlex.quote(c) for c in command)
    return result


class ToolUnavailable(Exception):
    """A tool resolves on PATH but a runtime dependency of it is missing."""

    def __init__(self, tool: str, message: str):
        super().__init__(message)
        self.tool = tool


def execute_binary_command(command, timeout: Optional[int] = None,
                           max_output_bytes: Optional[int] = None) -> Dict[str, Any]:
    """
    Run a command whose stdout is binary and return it base64-encoded.

    Deserialization payload generators emit raw serialized objects — a ysoserial
    payload starts with the bytes AC ED 00 05 — which are not valid UTF-8. The
    text-mode executor silently mangles that into an empty string, so these tools
    need a separate byte-preserving path.
    """
    effective_timeout = COMMAND_TIMEOUT if timeout is None else max(1, min(int(timeout), MAX_COMMAND_TIMEOUT))
    limit = MAX_OUTPUT_BYTES if max_output_bytes is None else int(max_output_bytes)
    rendered = command if isinstance(command, str) else " ".join(shlex.quote(c) for c in command)

    logger.info(f"Executing binary command: {rendered}")
    try:
        completed = subprocess.run(
            command,
            shell=isinstance(command, str),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=effective_timeout,
        )
        stdout_bytes, stderr_bytes, return_code, timed_out = (
            completed.stdout, completed.stderr, completed.returncode, False
        )
    except subprocess.TimeoutExpired as e:
        stdout_bytes = e.stdout or b""
        stderr_bytes = e.stderr or b""
        return_code, timed_out = -1, True
        logger.warning(f"Binary command timed out after {effective_timeout}s")
    except Exception as e:
        logger.error(f"Error executing binary command: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "stdout": "", "stdout_base64": "", "stdout_bytes": 0,
            "stderr": f"Error executing command: {str(e)}",
            "return_code": -1, "success": False, "timed_out": False,
            "partial_results": False, "command": rendered,
        }

    truncated = False
    if 0 < limit < len(stdout_bytes):
        stdout_bytes = stdout_bytes[:limit]
        truncated = True

    stderr_text, stderr_truncated = _truncate(stderr_bytes.decode("utf-8", errors="replace"), limit)

    result = {
        # base64 is the payload; keep `stdout` empty so nothing downstream tries
        # to read mangled text.
        "stdout": "",
        "stdout_base64": base64.b64encode(stdout_bytes).decode("ascii"),
        "stdout_bytes": len(stdout_bytes),
        "encoding": "base64",
        "stderr": stderr_text,
        "return_code": return_code,
        "success": bool(stdout_bytes) if timed_out else (return_code == 0),
        "timed_out": timed_out,
        "partial_results": timed_out and bool(stdout_bytes),
        "command": rendered,
    }
    if truncated or stderr_truncated:
        result["truncated"] = True
    return result


def missing_tool_response(tool: str, hint: str = "") -> Dict[str, Any]:
    """Uniform payload for a tool that is not installed on this host."""
    message = f"'{tool}' is not installed or not on PATH."
    if hint:
        message += f" {hint}"
    message += " Run install-tools.sh on this host to provision it."
    logger.warning(message)
    return {
        "stdout": "",
        "stderr": message,
        "return_code": 127,
        "success": False,
        "timed_out": False,
        "partial_results": False,
        "tool_missing": tool,
    }


def tool_endpoint(tool_name: str, required_params: Optional[List[str]] = None,
                  binary: Optional[str] = None, install_hint: str = ""):
    """
    Wrap a tool handler with the boilerplate every endpoint here repeats:
    JSON parsing, required-parameter checks, binary availability, and error handling.

    The wrapped function receives the request params dict and returns either a
    command (list) or a (command, options) tuple.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper():
            try:
                params = request.get_json(silent=True) or {}

                for name in (required_params or []):
                    if not params.get(name):
                        logger.warning(f"{tool_name} called without {name} parameter")
                        return jsonify({"error": f"{name} parameter is required"}), 400

                probe = binary or tool_name
                if not resolve_binary(probe):
                    return jsonify(missing_tool_response(probe, install_hint)), 200

                built = func(params)
                if built is None:
                    return jsonify({"error": "Failed to build command"}), 400
                if isinstance(built, tuple) and len(built) == 2 and isinstance(built[1], dict):
                    command, options = built
                else:
                    command, options = built, {}

                common = {
                    "timeout": params.get("timeout") or options.get("timeout"),
                    "max_output_bytes": params.get("max_output_bytes"),
                }
                if options.get("binary"):
                    result = execute_binary_command(command, **common)
                else:
                    result = execute_command(command, stdin_data=options.get("stdin"), **common)
                return jsonify(result)
            except ToolUnavailable as e:
                # Same shape as a missing binary so callers handle one case.
                logger.warning(str(e))
                return jsonify({
                    "stdout": "",
                    "stderr": str(e),
                    "return_code": 127,
                    "success": False,
                    "timed_out": False,
                    "partial_results": False,
                    "tool_missing": e.tool,
                }), 200
            except ValueError as e:
                # Raised by handlers for bad enum values / malformed input.
                logger.warning(f"Invalid input for {tool_name}: {str(e)}")
                return jsonify({"error": str(e)}), 400
            except Exception as e:
                logger.error(f"Error in {tool_name} endpoint: {str(e)}")
                logger.error(traceback.format_exc())
                return jsonify({"error": f"Server error: {str(e)}"}), 500
        return wrapper
    return decorator


def add_args(command: List[str], additional_args: str) -> List[str]:
    """Append free-form extra arguments. Safe because commands never use a shell."""
    if additional_args:
        command += shlex.split(additional_args)
    return command


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = ["nmap"] + shlex.split(scan_type)

        if ports:
            command += ["-p", ports]

        if additional_args:
            command += shlex.split(additional_args)

        command.append(target)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        # Soft-404 handling. Gobuster has no autocalibration equivalent to ffuf's
        # -ac, so a host answering 200 for every path has to be filtered by
        # response length instead.
        if params.get("exclude_length"):
            command += ["--exclude-length", str(params["exclude_length"])]
        if params.get("status_codes"):
            command += ["-s", str(params["status_codes"])]
        if params.get("status_codes_blacklist"):
            command += ["-b", str(params["status_codes_blacklist"])]

        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command, timeout=params.get("timeout"))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = ["dirb", url, wordlist]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = ["nikto", "-h", target]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
@tool_endpoint("sqlmap", required_params=["url"])
def sqlmap(params):
    """Execute sqlmap with the provided parameters."""
    command = ["sqlmap", "-u", params["url"], "--batch"]

    if params.get("data"):
        command += ["--data", params["data"]]
    if params.get("cookie"):
        command += ["--cookie", params["cookie"]]
    for header in params.get("headers", []) or []:
        command += ["-H", header]
    if params.get("method"):
        command += ["--method", params["method"]]
    if params.get("level"):
        command += ["--level", str(int(params["level"]))]
    if params.get("risk"):
        command += ["--risk", str(int(params["risk"]))]
    if params.get("technique"):
        command += ["--technique", params["technique"]]
    if params.get("dbms"):
        command += ["--dbms", params["dbms"]]
    if params.get("tamper"):
        command += ["--tamper", params["tamper"]]
    if params.get("threads"):
        command += ["--threads", str(int(params["threads"]))]
    if params.get("proxy"):
        command += ["--proxy", params["proxy"]]

    # Common enumeration shortcuts, so callers do not have to know the flags.
    for flag, option in (
        ("dbs", "--dbs"),
        ("tables", "--tables"),
        ("columns", "--columns"),
        ("dump", "--dump"),
        ("current_user", "--current-user"),
        ("current_db", "--current-db"),
        ("passwords", "--passwords"),
        ("is_dba", "--is-dba"),
    ):
        if params.get(flag):
            command.append(option)

    if params.get("db"):
        command += ["-D", params["db"]]
    if params.get("table"):
        command += ["-T", params["table"]]
    if params.get("column"):
        command += ["-C", params["column"]]

    return add_args(command, params.get("additional_args", ""))


@app.route("/api/tools/ffuf", methods=["POST"])
@tool_endpoint("ffuf", required_params=["url"])
def ffuf(params):
    """Execute ffuf web fuzzer with the provided parameters."""
    url = params["url"]
    wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

    # ffuf needs an explicit FUZZ marker; default to appending a path fuzz point
    # rather than failing, which is what a caller almost always means.
    if "FUZZ" not in url and not params.get("headers") and not params.get("data"):
        url = url.rstrip("/") + "/FUZZ"

    command = ["ffuf", "-u", url, "-w", wordlist]

    if params.get("method"):
        command += ["-X", params["method"]]
    for header in params.get("headers", []) or []:
        command += ["-H", header]
    if params.get("data"):
        command += ["-d", params["data"]]
    if params.get("extensions"):
        command += ["-e", params["extensions"]]
    if params.get("threads"):
        command += ["-t", str(int(params["threads"]))]
    if params.get("rate"):
        command += ["-rate", str(int(params["rate"]))]
    if params.get("recursion"):
        command += ["-recursion"]
        if params.get("recursion_depth"):
            command += ["-recursion-depth", str(int(params["recursion_depth"]))]

    # Matchers and filters
    if params.get("match_codes"):
        command += ["-mc", params["match_codes"]]
    if params.get("match_size"):
        command += ["-ms", params["match_size"]]
    if params.get("match_regex"):
        command += ["-mr", params["match_regex"]]
    if params.get("filter_codes"):
        command += ["-fc", params["filter_codes"]]
    if params.get("filter_size"):
        command += ["-fs", params["filter_size"]]
    if params.get("filter_words"):
        command += ["-fw", params["filter_words"]]
    if params.get("filter_lines"):
        command += ["-fl", params["filter_lines"]]
    if params.get("filter_regex"):
        command += ["-fr", params["filter_regex"]]

    # Autocalibration: ffuf requests known-bogus paths first and derives filters
    # from the responses. This is the reliable answer to a host that returns 200
    # for everything, where fixed filters would let thousands of soft-404s through.
    if params.get("auto_calibrate") or params.get("auto_calibrate_strategy") or params.get("auto_calibrate_per_host"):
        command.append("-ac")
    if params.get("auto_calibrate_per_host"):
        command.append("-ach")
    if params.get("auto_calibrate_strategy"):
        strategy = params["auto_calibrate_strategy"]
        for entry in ([strategy] if isinstance(strategy, str) else strategy):
            if not re.match(r'^[a-z0-9_.-]+$', entry):
                raise ValueError(f"invalid auto-calibration strategy: {entry}")
            command += ["-acs", entry]

    # Non-interactive, machine-readable defaults.
    command += ["-s"] if params.get("silent") else []
    if params.get("json_output", True):
        command += ["-json"]
    command += ["-noninteractive"]

    return add_args(command, params.get("additional_args", ""))


@app.route("/api/tools/shcheck", methods=["POST"])
@tool_endpoint("shcheck", required_params=["target"],
               install_hint="Install with: pipx install shcheck.")
def shcheck(params):
    """Execute shcheck security-header checker against one or more targets."""
    targets = params["target"]
    targets = [targets] if isinstance(targets, str) else list(targets)

    command = ["shcheck"]

    if params.get("json_output", True):
        command.append("-j")
    if params.get("disable_ssl_check"):
        command.append("-d")
    if params.get("information"):
        command.append("-i")
    if params.get("caching"):
        command.append("-x")
    if params.get("hide_positive"):
        command.append("-p")
    for header in params.get("headers", []) or []:
        command += ["-a", header]
    if params.get("cookie"):
        command += ["-c", params["cookie"]]
    if params.get("proxy"):
        command += ["--proxy", params["proxy"]]

    command = add_args(command, params.get("additional_args", ""))
    command += targets
    return command


@app.route("/api/tools/jsanalyzer", methods=["POST"])
@tool_endpoint("jsanalyzer", required_params=["targets"],
               install_hint="Provided by this repo at tools/jsanalyzer.py.")
def jsanalyzer(params):
    """Extract endpoints, URLs, secrets and file references from JavaScript."""
    targets = params["targets"]
    targets = [targets] if isinstance(targets, str) else list(targets)

    command = ["jsanalyzer", "--json"]

    if params.get("categories"):
        categories = params["categories"]
        command += ["--categories", categories if isinstance(categories, str) else ",".join(categories)]
    if params.get("include_low_confidence"):
        command.append("--include-low-confidence")
    if params.get("mask"):
        command.append("--mask")
    if params.get("insecure"):
        command.append("--insecure")
    for header in params.get("headers", []) or []:
        command += ["-H", header]
    if params.get("threads"):
        command += ["--threads", str(int(params["threads"]))]
    if params.get("fetch_timeout"):
        command += ["--timeout", str(int(params["fetch_timeout"]))]

    command = add_args(command, params.get("additional_args", ""))
    command += targets
    return command


@app.route("/api/tools/bangbang", methods=["POST"])
@tool_endpoint("bangbang", required_params=["target"],
               install_hint="Install with install-tools.sh --only bangbang.")
def bangbang(params):
    """Search NVD for a product's CVEs, then hunt public PoCs across four forges."""
    target = params["target"]
    # The tool takes either a keyword or a CVE ID as its single positional arg.
    # Reject shell-ish input early even though nothing here uses a shell.
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,80}$', target):
        raise ValueError("target must be a product keyword or a CVE ID")

    command = ["bangbang", target]

    if params.get("max_cves"):
        command += ["--max-cves", str(int(params["max_cves"]))]
    if params.get("max_hits") is not None:
        command += ["--max-hits", str(int(params["max_hits"]))]
    if params.get("min_stars"):
        command += ["--min-stars", str(int(params["min_stars"]))]
    if params.get("threshold") is not None:
        command += ["--threshold", str(int(params["threshold"]))]
    if params.get("show_all"):
        command.append("--show-all")
    if params.get("sources"):
        sources = params["sources"]
        sources = sources if isinstance(sources, str) else ",".join(sources)
        valid = {"gh", "glab", "cb", "edb", "github", "gitlab", "codeberg", "exploitdb"}
        unknown = {s.strip() for s in sources.split(",") if s.strip()} - valid
        if unknown:
            raise ValueError(f"unknown sources: {', '.join(sorted(unknown))}")
        command += ["--sources", sources]
    if params.get("nvd_api_key"):
        command += ["--nvd-api-key", params["nvd_api_key"]]

    download_dir = params.get("download_dir", "")
    if download_dir:
        command += ["--dir", download_dir]

    command = add_args(command, params.get("additional_args", ""))

    # bangbang prints its results and then drops into a REPL. Its first-run
    # wizard is TTY-gated and the REPL exits on stdin EOF, so the default
    # stdin=/dev/null already yields a clean one-shot search. To download, drive
    # that same REPL by feeding it commands.
    select = params.get("select")
    stdin_lines = []
    if select:
        targets = select if isinstance(select, str) else " ".join(select)
        # Targets are "N" or "N.M" only; anything else would be a REPL command
        # smuggled in through this field.
        if not re.match(r'^[0-9]+(\.[0-9]+)?( +[0-9]+(\.[0-9]+)?)*$', targets.strip()):
            raise ValueError("select must be space-separated targets like '1' or '2.3'")
        stdin_lines += [f"select {targets.strip()}", "download"]
    stdin_lines.append("quit")

    # Searching many CVEs across four hosts is slow; NVD alone rate-limits hard
    # without an API key.
    return command, {"stdin": "\n".join(stdin_lines) + "\n", "timeout": 900}


@app.route("/api/tools/webcapture", methods=["POST"])
@tool_endpoint("webcapture", required_params=["url"],
               install_hint="Provided by this repo; run install-tools.sh --only webcapture.")
def webcapture(params):
    """Render a URL in headless Chromium and capture recon data."""
    command = ["webcapture", params["url"]]

    if params.get("browser"):
        browser = params["browser"]
        if browser not in ("chromium", "firefox", "webkit"):
            raise ValueError("browser must be chromium, firefox, or webkit")
        command += ["--browser", browser]
    if params.get("capture"):
        capture = params["capture"]
        command += ["--capture", capture if isinstance(capture, str) else ",".join(capture)]
    if params.get("wait_until"):
        wait_until = params["wait_until"]
        if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
            raise ValueError("wait_until must be load, domcontentloaded, networkidle, or commit")
        command += ["--wait-until", wait_until]
    if params.get("wait_ms"):
        command += ["--wait-ms", str(int(params["wait_ms"]))]
    if params.get("nav_timeout"):
        command += ["--timeout", str(int(params["nav_timeout"]))]
    for header in params.get("headers", []) or []:
        command += ["-H", header]
    if params.get("cookie"):
        command += ["--cookie", params["cookie"]]
    if params.get("user_agent"):
        command += ["--user-agent", params["user_agent"]]
    if params.get("viewport"):
        command += ["--viewport", params["viewport"]]
    if params.get("proxy"):
        command += ["--proxy", params["proxy"]]
    if params.get("insecure"):
        command.append("--insecure")
    if params.get("full_page"):
        command.append("--full-page")
    if params.get("exec_js"):
        command += ["--exec-js", params["exec_js"]]
    if params.get("max_dom_bytes") is not None:
        command += ["--max-dom-bytes", str(int(params["max_dom_bytes"]))]
    if params.get("max_requests"):
        command += ["--max-requests", str(int(params["max_requests"]))]

    # A browser launch plus network idle regularly exceeds the default timeout.
    return add_args(command, params.get("additional_args", "")), {"timeout": 300}


@app.route("/api/tools/sourcemapper", methods=["POST"])
@tool_endpoint("sourcemapper",
               install_hint="Install with: go install github.com/denandz/sourcemapper@latest.")
def sourcemapper(params):
    """Reconstruct a JavaScript source tree from a sourcemap."""
    url = params.get("url", "")
    jsfile = params.get("jsfile", "")
    if not url and not jsfile:
        raise ValueError("Either url or jsfile parameter is required")

    output_dir = params.get("output_dir", "")
    if not output_dir:
        # Keep runs isolated so repeated calls do not collide; sourcemapper
        # refuses to write into a directory that already exists.
        output_dir = os.path.join("/tmp", f"sourcemapper_{os.getpid()}_{threading.get_ident()}")

    command = ["sourcemapper", "-output", output_dir]

    if url:
        command += ["-url", url]
    else:
        command += ["-jsfile", jsfile]

    if params.get("insecure"):
        command.append("-insecure")
    if params.get("verbose"):
        command.append("-verbose")

    return add_args(command, params.get("additional_args", ""))


@app.route("/api/tools/trufflehog", methods=["POST"])
@tool_endpoint("trufflehog", required_params=["target"])
def trufflehog(params):
    """Scan a git repo, filesystem path, or other source for verified secrets."""
    mode = params.get("mode", "filesystem")
    valid_modes = {
        "git", "github", "gitlab", "filesystem", "s3", "gcs",
        "docker", "circleci", "syslog", "jenkins", "postman", "elasticsearch",
    }
    if mode not in valid_modes:
        raise ValueError(f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(valid_modes))}")

    command = ["trufflehog", mode]

    # Each source takes its target differently.
    if mode in ("github", "gitlab"):
        # A full repo URL scans one repo; a bare name is treated as an org/group.
        scope = params.get("scope") or ("repo" if params["target"].startswith("http") else "org")
        if scope not in ("repo", "org"):
            raise ValueError("scope must be 'repo' or 'org'")
        command += [f"--{scope}", params["target"]]
    elif mode == "s3":
        command += ["--bucket", params["target"]]
    elif mode == "docker":
        command += ["--image", params["target"]]
    elif mode == "git":
        # The git source takes a URI, not a path: a bare /path/to/repo is
        # rejected with "unsupported Git URI". Normalise local paths to file://.
        target = params["target"]
        if os.path.isdir(target):
            target = "file://" + os.path.abspath(target)
        command.append(target)
    else:
        command.append(params["target"])

    if params.get("only_verified", True):
        command.append("--only-verified")
    if params.get("json_output", True):
        command.append("--json")
    if params.get("no_update", True):
        command.append("--no-update")
    if params.get("concurrency"):
        command += ["--concurrency", str(int(params["concurrency"]))]
    if params.get("since_commit"):
        command += ["--since-commit", params["since_commit"]]
    if params.get("branch"):
        command += ["--branch", params["branch"]]
    if params.get("max_depth"):
        command += ["--max-depth", str(int(params["max_depth"]))]
    if params.get("include_detectors"):
        command += ["--include-detectors", params["include_detectors"]]
    if params.get("exclude_detectors"):
        command += ["--exclude-detectors", params["exclude_detectors"]]

    return add_args(command, params.get("additional_args", ""))


@app.route("/api/tools/semgrep", methods=["POST"])
@tool_endpoint("semgrep", required_params=["target"],
               install_hint="Install with: pipx install semgrep.")
def semgrep(params):
    """Run Semgrep static analysis over a path."""
    command = ["semgrep", "scan"]

    config = params.get("config", "auto")
    for entry in ([config] if isinstance(config, str) else config):
        command += ["--config", entry]

    if params.get("json_output", True):
        command.append("--json")
    if params.get("severity"):
        severities = params["severity"]
        for level in ([severities] if isinstance(severities, str) else severities):
            command += ["--severity", level]
    if params.get("exclude"):
        excludes = params["exclude"]
        for pattern in ([excludes] if isinstance(excludes, str) else excludes):
            command += ["--exclude", pattern]
    if params.get("include"):
        includes = params["include"]
        for pattern in ([includes] if isinstance(includes, str) else includes):
            command += ["--include", pattern]
    if params.get("jobs"):
        command += ["--jobs", str(int(params["jobs"]))]
    if params.get("max_target_bytes"):
        command += ["--max-target-bytes", str(int(params["max_target_bytes"]))]
    if params.get("no_git_ignore"):
        command.append("--no-git-ignore")

    # Semgrep is interactive and telemetry-enabled by default; neither suits a
    # headless API call.
    command += ["--quiet", "--metrics", "off", "--disable-version-check"]

    command = add_args(command, params.get("additional_args", ""))
    command.append(params["target"])
    return command


@app.route("/api/tools/ysoserial", methods=["POST"])
@tool_endpoint("ysoserial",
               install_hint="Needs a JRE plus ysoserial-all.jar.")
def ysoserial(params):
    """Generate a Java deserialization payload with ysoserial."""
    # No gadget means "show me what is available", which is a common first call.
    if params.get("list_gadgets") or not params.get("gadget"):
        return ["ysoserial"]

    gadget = params["gadget"]
    if not re.match(r'^[A-Za-z0-9_.-]+$', gadget):
        raise ValueError("Invalid gadget name")

    command = ["ysoserial", gadget]
    if params.get("command"):
        command.append(params["command"])

    command = add_args(command, params.get("additional_args", ""))
    # Payload bytes are raw Java serialization, so return them base64-encoded.
    return command, {"binary": True}


@app.route("/api/tools/ysoserial_net", methods=["POST"])
@tool_endpoint("ysoserial_net", binary="ysoserial-net",
               install_hint="Needs mono plus the ysoserial.net release; see install-tools.sh.")
def ysoserial_net(params):
    """Generate a .NET deserialization payload with ysoserial.net (via Mono)."""
    # The installed `ysoserial-net` is a shell wrapper around `mono foo.exe`, so
    # it resolves on PATH even when Mono itself is absent. Check the real
    # dependency here rather than letting the wrapper fail with a bare
    # "mono: not found" and exit 127.
    if not resolve_binary("mono"):
        raise ToolUnavailable(
            "mono",
            "ysoserial.net requires Mono, which is not installed. "
            "Install it with: sudo apt-get install -y mono-runtime libmono-system-runtime4.0-cil"
        )

    if params.get("list_gadgets"):
        return ["ysoserial-net", "-h"]

    command = ["ysoserial-net"]

    if params.get("gadget"):
        gadget = params["gadget"]
        if not re.match(r'^[A-Za-z0-9_.-]+$', gadget):
            raise ValueError("Invalid gadget name")
        command += ["-g", gadget]
    if params.get("formatter"):
        formatter = params["formatter"]
        if not re.match(r'^[A-Za-z0-9_.-]+$', formatter):
            raise ValueError("Invalid formatter name")
        command += ["-f", formatter]
    if params.get("command"):
        command += ["-c", params["command"]]
    if params.get("output_format"):
        command += ["-o", params["output_format"]]
    if params.get("test"):
        command.append("-t")
    if params.get("plugin"):
        command += ["-p", params["plugin"]]

    command = add_args(command, params.get("additional_args", ""))
    # With -o raw the output is binary; base64 keeps it intact over JSON.
    return command, {"binary": params.get("output_format", "") != "base64"}


@app.route("/api/tools/nuclei", methods=["POST"])
@tool_endpoint("nuclei", required_params=["target"])
def nuclei(params):
    """Run Nuclei template-based vulnerability scanning."""
    targets = params["target"]
    targets = [targets] if isinstance(targets, str) else list(targets)

    command = ["nuclei"]
    for target in targets:
        command += ["-u", target]

    if params.get("templates"):
        templates = params["templates"]
        for entry in ([templates] if isinstance(templates, str) else templates):
            command += ["-t", entry]
    if params.get("exclude_templates"):
        excludes = params["exclude_templates"]
        for entry in ([excludes] if isinstance(excludes, str) else excludes):
            command += ["-et", entry]
    if params.get("severity"):
        command += ["-severity", params["severity"]]
    if params.get("tags"):
        command += ["-tags", params["tags"]]
    if params.get("exclude_tags"):
        command += ["-etags", params["exclude_tags"]]
    if params.get("protocols"):
        command += ["-type", params["protocols"]]
    if params.get("rate_limit"):
        command += ["-rate-limit", str(int(params["rate_limit"]))]
    if params.get("concurrency"):
        command += ["-c", str(int(params["concurrency"]))]
    if params.get("retries"):
        command += ["-retries", str(int(params["retries"]))]
    for header in params.get("headers", []) or []:
        command += ["-H", header]
    if params.get("proxy"):
        command += ["-proxy", params["proxy"]]
    if params.get("json_output", True):
        command.append("-jsonl")
    if params.get("update_templates"):
        command.append("-update-templates")
    else:
        # Update checks on every call are slow and can stall without a TTY.
        command.append("-disable-update-check")
    if params.get("no_interactsh"):
        command.append("-no-interactsh")

    command += ["-silent", "-no-color"]

    return add_args(command, params.get("additional_args", ""))


@app.route("/api/tools/sslscan", methods=["POST"])
@tool_endpoint("sslscan", required_params=["target"])
def sslscan(params):
    """Enumerate TLS versions, ciphers and certificate details for a host."""
    command = ["sslscan", "--no-colour"]

    if params.get("xml_output"):
        command.append("--xml=-")
    if params.get("show_certificate", True):
        command.append("--show-certificate")
    if params.get("show_ciphers"):
        command.append("--show-ciphers")
    if params.get("starttls"):
        protocol = params["starttls"]
        if not re.match(r'^[a-z0-9]+$', protocol):
            raise ValueError("Invalid starttls protocol")
        command.append(f"--starttls-{protocol}")
    if params.get("sni_name"):
        command += [f"--sni={params['sni_name']}"]
    if params.get("ipv4"):
        command.append("--ipv4")
    if params.get("ipv6"):
        command.append("--ipv6")

    command = add_args(command, params.get("additional_args", ""))
    command.append(params["target"])
    return command

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Validate module name (allow only alphanumeric, slashes, underscores, hyphens)
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"error": "Invalid module name"}), 400

        # Create an MSF resource script with validated options
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Validate option keys
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = ["hydra", "-t", "4"]

        if username:
            command += ["-l", username]
        elif username_file:
            command += ["-L", username_file]

        if password:
            command += ["-p", password]
        elif password_file:
            command += ["-P", password_file]

        command += [target, service]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = ["john"]

        if format_type:
            command.append(f"--format={format_type}")

        if wordlist:
            command.append(f"--wordlist={wordlist}")

        if additional_args:
            command += shlex.split(additional_args)

        command.append(hash_file)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = ["wpscan", "--url", url]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = ["enum4linux"] + shlex.split(additional_args) + [target]
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Tools this server exposes an endpoint for. The value is the binary to probe,
# which differs from the endpoint name for the Mono-wrapped .NET tool.
ESSENTIAL_TOOLS = ["nmap", "gobuster", "dirb", "nikto"]
EXTENDED_TOOLS = {
    "sqlmap": "sqlmap",
    "ffuf": "ffuf",
    "shcheck": "shcheck",
    "jsanalyzer": "jsanalyzer",
    "sourcemapper": "sourcemapper",
    "trufflehog": "trufflehog",
    "semgrep": "semgrep",
    "ysoserial": "ysoserial",
    "ysoserial_net": "ysoserial-net",
    "nuclei": "nuclei",
    "sslscan": "sslscan",
    "webcapture": "webcapture",
    "bangbang": "bangbang",
}


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # shutil.which is a PATH lookup, so this stays cheap even with many tools.
    tools_status = {tool: bool(resolve_binary(tool)) for tool in ESSENTIAL_TOOLS}
    extended_status = {name: bool(resolve_binary(binary)) for name, binary in EXTENDED_TOOLS.items()}

    # Some tools are shell wrappers around an interpreter, so the wrapper being
    # present on PATH is not enough to call them usable.
    for name, runtime in (("ysoserial", "java"), ("ysoserial_net", "mono")):
        if extended_status.get(name) and not resolve_binary(runtime):
            extended_status[name] = False

    all_essential_tools_available = all(tools_status.values())
    missing_extended = sorted(name for name, ok in extended_status.items() if not ok)

    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "extended_tools_status": extended_status,
        "missing_extended_tools": missing_extended,
        "all_extended_tools_available": not missing_extended,
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind the server to (default: 127.0.0.1 for localhost only)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
