#!/usr/bin/env python3
"""Tool abstraction layer for Jarvis.

Provides a unified run_tool(name, args) interface for all tools
the pipeline and ask.py need: shell, file ops, web, etc.
"""

import subprocess
import sys
import os
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional
from pathlib import Path


@dataclass
class ToolResult:
    success: bool
    output: str
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "metadata": self.metadata,
        }


_registry: Dict[str, Callable] = {}


def register_tool(name: str):
    """Decorator to register a tool handler."""
    def decorator(fn):
        _registry[name] = fn
        return fn
    return decorator


def run_tool(name: str, args: Optional[dict] = None) -> ToolResult:
    """Run a registered tool by name."""
    if name not in _registry:
        return ToolResult(False, "", f"Unknown tool: {name}")
    try:
        return _registry[name](args or {})
    except Exception as e:
        return ToolResult(False, "", f"{type(e).__name__}: {e}")


def list_tools() -> list:
    """Return list of registered tool names."""
    return sorted(_registry.keys())


# ──────────────────────────────────────────────────────────────────────
# Shell execution
# ──────────────────────────────────────────────────────────────────────

@register_tool("shell")
def _tool_shell(args: dict) -> ToolResult:
    """Execute a shell command inside the Docker container.

    Args:
        command (str): The shell command to run.
        timeout (int): Timeout in seconds (default 30).
        workdir (str): Working directory inside container (default /workspace).
    """
    command = args.get("command", "")
    if not command:
        return ToolResult(False, "", "No command provided")

    timeout = args.get("timeout", 30)
    workdir = args.get("workdir", "/workspace")

    try:
        import docker_env
        exit_code, stdout, stderr = docker_env.exec_command(
            f"cd {workdir} && {command}",
            timeout=timeout,
            demux=True,
        )
        output = stdout.strip()
        err = stderr.strip()
        combined = output + ("\n--- STDERR ---\n" + err if err else "")
        if exit_code != 0 and not combined:
            combined = f"Exit code: {exit_code}"
        return ToolResult(
            success=(exit_code == 0),
            output=combined[:8000],
            error=err[:2000] if exit_code != 0 else "",
            metadata={"exit_code": exit_code},
        )
    except Exception as e:
        return ToolResult(False, "", str(e))


@register_tool("shell_host")
def _tool_shell_host(args: dict) -> ToolResult:
    """Execute a shell command on the host machine (not Docker)."""
    command = args.get("command", "")
    if not command:
        return ToolResult(False, "", "No command provided")

    timeout = args.get("timeout", 30)

    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout.strip()
        err = result.stderr.strip()
        combined = output + ("\n--- STDERR ---\n" + err if err else "")
        return ToolResult(
            success=(result.returncode == 0),
            output=combined[:8000],
            error=err[:2000] if result.returncode != 0 else "",
            metadata={"exit_code": result.returncode},
        )
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"Command timed out after {timeout}s")
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# File operations (Docker container)
# ──────────────────────────────────────────────────────────────────────

@register_tool("file_read")
def _tool_file_read(args: dict) -> ToolResult:
    """Read a file from the Docker container."""
    path = args.get("path", "")
    if not path:
        return ToolResult(False, "", "No path provided")

    try:
        import docker_env
        content = docker_env.read_file(path)
        return ToolResult(True, content[:50000])
    except FileNotFoundError:
        return ToolResult(False, "", f"File not found: {path}")
    except Exception as e:
        return ToolResult(False, "", str(e))


@register_tool("file_write")
def _tool_file_write(args: dict) -> ToolResult:
    """Write content to a file in the Docker container."""
    path = args.get("path", "")
    content = args.get("content", "")
    if not path:
        return ToolResult(False, "", "No path provided")

    try:
        import docker_env
        docker_env.write_file(path, content)
        return ToolResult(True, f"Wrote {len(content)} bytes to {path}")
    except Exception as e:
        return ToolResult(False, "", str(e))


@register_tool("file_list")
def _tool_file_list(args: dict) -> ToolResult:
    """List files in a directory inside the Docker container."""
    path = args.get("path", "/workspace")
    recursive = args.get("recursive", False)

    try:
        import docker_env
        files = docker_env.list_files(path, recursive=recursive)
        return ToolResult(True, "\n".join(files) if files else "Empty directory")
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# Run code (Docker container)
# ──────────────────────────────────────────────────────────────────────

@register_tool("run_code")
def _tool_run_code(args: dict) -> ToolResult:
    """Run code in the Docker container with automatic input wrapping.

    Args:
        code (str): Source code to run.
        language (str): Programming language (python, c, etc.).
        filename (str): Optional filename for context.
    """
    code = args.get("code", "")
    language = args.get("language", "python")
    filename = args.get("filename", "")

    if not code:
        return ToolResult(False, "", "No code provided")

    try:
        import docker_env
        result = docker_env.run_code(code, language, filename=filename)
        if isinstance(result, dict):
            success = result.get("exit_code", 1) == 0
            output = result.get("output", "")[:8000]
            error = result.get("stderr", "")[:2000] if not success else ""
            return ToolResult(success, output, error, {"exit_code": result.get("exit_code", 1)})
        return ToolResult(True, str(result)[:8000])
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# Terminal display
# ──────────────────────────────────────────────────────────────────────

@register_tool("terminal")
def _tool_terminal(args: dict) -> ToolResult:
    """Send a message to the Jarvis terminal display."""
    message = args.get("message", "")
    color = args.get("color", "33")  # 33=yellow, 36=cyan, 32=green, 31=red

    try:
        from pipeline import _send_to_terminal
        _send_to_terminal(f'echo "\\n\\033[1;{color}m{message}\\033[0m"')
        return ToolResult(True, f"Sent to terminal: {message}")
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# Host operations (xdg-open, ssh, etc.)
# ──────────────────────────────────────────────────────────────────────

@register_tool("xdg_open")
def _tool_xdg_open(args: dict) -> ToolResult:
    """Open a URL in the default browser on the host."""
    url = args.get("url", "")
    if not url:
        return ToolResult(False, "", "No URL provided")

    try:
        subprocess.Popen(
            ["xdg-open", url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return ToolResult(True, f"Opened {url}")
    except Exception as e:
        return ToolResult(False, "", str(e))


@register_tool("ssh")
def _tool_ssh(args: dict) -> ToolResult:
    """Run a command on the Raspberry Pi via SSH."""
    command = args.get("command", "")
    if not command:
        return ToolResult(False, "", "No command provided")

    try:
        from config import PI_USER, PI_HOST
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             f"{PI_USER}@{PI_HOST}", command],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.strip()
        err = result.stderr.strip()
        return ToolResult(
            success=(result.returncode == 0),
            output=output[:4000],
            error=err[:1000] if result.returncode != 0 else "",
        )
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# Pipeline display
# ──────────────────────────────────────────────────────────────────────

@register_tool("pipeline_display")
def _tool_pipeline_display(args: dict) -> ToolResult:
    """Show a pipeline status message in the terminal."""
    message = args.get("message", "")
    try:
        from pipeline import _send_to_terminal
        _send_to_terminal(f'echo "\\n\\033[1;36m{message}\\033[0m"')
        return ToolResult(True, message)
    except Exception as e:
        return ToolResult(False, "", str(e))


# ──────────────────────────────────────────────────────────────────────
# Config/env helpers
# ──────────────────────────────────────────────────────────────────────

@register_tool("env")
def _tool_env(args: dict) -> ToolResult:
    """Get environment variables (non-sensitive ones)."""
    keys = args.get("keys", [])
    if keys:
        vals = {k: os.environ.get(k, "") for k in keys}
    else:
        safe_prefixes = ("JARVIS_", "HOME", "PATH", "LANG", "SHELL", "USER")
        vals = {k: v for k, v in os.environ.items()
                if any(k.startswith(p) for p in safe_prefixes)}
    return ToolResult(True, json.dumps(vals, indent=2))


# ──────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Registered tools:", list_tools())
    print()

    # Test shell
    r = run_tool("shell", {"command": "echo hello"})
    print(f"shell: {r.output.strip()}")

    # Test env
    r = run_tool("env", {"keys": ["HOME"]})
    print(f"env: {r.output.strip()}")
