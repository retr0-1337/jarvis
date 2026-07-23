#!/usr/bin/env python3
"""Docker development environment manager for Jarvis."""

import docker
import os
import io
import tarfile
import json
import re
import time
import threading

from config import WORKSPACE_DIR

CONTAINER_NAME = "jarvis-devbox"
IMAGE = "ubuntu:24.04"
WORKSPACE = str(WORKSPACE_DIR)
HOST_WORKSPACE = WORKSPACE

_client = None
_container = None


def get_client():
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def _fix_dns(container):
    """Set Google DNS inside container (Docker resets resolv.conf on restart).
    Skipped for --network host containers (they use host's resolv.conf)."""
    try:
        net_mode = container.attrs.get("HostConfig", {}).get("NetworkMode", "")
        if net_mode == "host":
            return  # Don't touch host's resolv.conf
        container.exec_run(["bash", "-c",
            "echo -e 'nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1' > /etc/resolv.conf"])
    except Exception:
        pass


def get_container():
    global _container
    if _container is not None:
        try:
            _container.reload()
            if _container.status == "running":
                return _container
        except docker.errors.NotFound:
            _container = None
    client = get_client()
    try:
        _container = client.containers.get(CONTAINER_NAME)
        if _container and _container.status == "running":
            _fix_dns(_container)
        return _container
    except docker.errors.NotFound:
        return None


def ensure_container():
    """Create or start the dev container. Returns (container, first_run)."""
    global _container
    os.makedirs(HOST_WORKSPACE, exist_ok=True)

    container = get_container()
    if container:
        if container.status != "running":
            container.start()
            container.reload()
        _fix_dns(container)
        return container, False

    client = get_client()
    _container = client.containers.run(
        IMAGE,
        command="sleep infinity",
        detach=True,
        name=CONTAINER_NAME,
        stdin_open=True,
        tty=True,
        working_dir="/workspace",
        network_mode="host",
        volumes={
            HOST_WORKSPACE: {"bind": "/workspace", "mode": "rw"},
        },
        restart_policy={"Name": "always"},
    )
    _container.reload()

    # Install dev tools in background
    threading.Thread(target=_install_tools, args=(_container,), daemon=True).start()
    return _container, True


def _install_tools(container):
    """Install build tools in the container."""
    tools = (
        "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "build-essential gcc g++ make cmake "
        "git curl wget "
        "python3 python3-pip "
        "nodejs npm "
        "file procps "
        "&& apt-get clean && rm -rf /var/lib/apt/lists/* "
        "&& echo 'DONE_INSTALLING'"
    )
    try:
        exit_code, output = container.exec_run(["bash", "-c", tools])
        last_line = b""
        for chunk in output:
            last_line = chunk
        if b"DONE_INSTALLING" in last_line:
            print("[Docker] Dev tools installed successfully")
        else:
            print(f"[Docker] Tool installation finished with code {exit_code}")
    except Exception as e:
        print(f"[Docker] Tool installation error: {e}")


def container_status():
    """Return container status info."""
    container = get_container()
    if not container:
        return {"exists": False, "status": "none", "tools_ready": False}
    tools_ready = False
    if container.status == "running":
        try:
            _, output = container.exec_run(["bash", "-c", "test -f /usr/bin/gcc && echo OK"])
            tools_ready = b"OK" in output
        except Exception:
            pass
    return {
        "exists": True,
        "status": container.status,
        "tools_ready": tools_ready,
    }


def exec_command(cmd, workdir="/workspace", timeout=30, demux=False):
    """Execute a command and return (exit_code, output_string).
    If demux=True, returns (exit_code, stdout_string, stderr_string).
    Enforces timeout via 'timeout' bash wrapper — kills hanging processes."""
    container = get_container()
    if not container:
        if demux:
            return -1, "Container not running.", ""
        return -1, "Container not running."
    # Write command to a temp script and run via 'timeout' to avoid quoting issues
    import shlex
    script_cmd = f"timeout --signal=TERM --kill-after=2 {timeout} bash -c {shlex.quote(cmd)}"
    try:
        exit_code, output = container.exec_run(
            ["bash", "-c", script_cmd],
            workdir=workdir,
            demux=demux,
        )
        if demux:
            stdout = (output[0] or b"").decode(errors="replace")
            stderr = (output[1] or b"").decode(errors="replace")
            return exit_code, stdout, stderr
        return exit_code, output.decode(errors="replace")
    except Exception as e:
        if demux:
            return -1, str(e), ""
        return -1, str(e)


def exec_command_stream(cmd, workdir="/workspace"):
    """Execute a command and yield output lines as they come."""
    container = get_container()
    if not container:
        yield "Container not running.\n"
        return
    exec_instance = get_client().api.exec_create(
        container.id,
        cmd=["bash", "-c", cmd],
        workdir=workdir,
        stdout=True,
        stderr=True,
    )
    output = get_client().api.exec_start(exec_instance["Id"], stream=True)
    for chunk in output:
        yield chunk.decode(errors="replace")
    output._response.close() if hasattr(output, "_response") else None


def write_file(path, content, workdir="/workspace"):
    """Write a file into the container."""
    container = get_container()
    if not container:
        return False
    if isinstance(content, str):
        content = content.encode("utf-8")
    # Ensure parent directory exists
    parent = os.path.dirname(path)
    if parent:
        exec_command(f"mkdir -p {parent}", timeout=10)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        info = tarfile.TarInfo(name=os.path.basename(path))
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    tar_buffer.seek(0)
    container.put_archive(parent or workdir, tar_buffer)
    return True


def read_file(path):
    """Read a file from the container. Returns content string or None."""
    container = get_container()
    if not container:
        return None
    try:
        bits, stat = container.get_archive(path)
        tar_data = io.BytesIO()
        for chunk in bits:
            tar_data.write(chunk)
        tar_data.seek(0)
        with tarfile.open(fileobj=tar_data) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        return f.read().decode(errors="replace")
        return None
    except Exception:
        return None


def list_files(path="/workspace", recursive=False):
    """List files and directories. Returns list of dicts."""
    container = get_container()
    if not container:
        return []
    if recursive:
        cmd = f"find '{path}' -maxdepth 3 -printf '%y %p\\n' 2>/dev/null | head -200"
    else:
        cmd = f"ls -la '{path}' 2>/dev/null"
    _, output = exec_command(cmd)
    entries = []
    if recursive:
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2:
                ftype, fpath = parts
                entries.append({
                    "path": fpath,
                    "name": os.path.basename(fpath),
                    "type": "dir" if ftype == "d" else "file",
                })
    else:
        for line in output.strip().split("\n"):
            if not line.strip() or line.startswith("total"):
                continue
            parts = line.split(None, 8)
            if len(parts) >= 9:
                is_dir = parts[0].startswith("d")
                name = parts[8]
                if name in (".", ".."):
                    continue
                entries.append({
                    "path": os.path.join(path, name),
                    "name": name,
                    "type": "dir" if is_dir else "file",
                    "size": parts[4] if len(parts) > 4 else "0",
                    "permissions": parts[0],
                })
    return entries


def _escape_code_newlines(code: str) -> str:
    """Fix \\n inside string literals that became real newlines from JSON parsing."""
    result = []
    i = 0
    in_string = None
    escape_next = False
    while i < len(code):
        ch = code[i]
        if in_string:
            if escape_next:
                result.append(ch)
                escape_next = False
            elif ch == '\\':
                result.append(ch)
                escape_next = True
            elif ch == '\n':
                result.append('\\')
                result.append('n')
            elif in_string in ('"""', "'''"):
                if code[i:i+3] == in_string:
                    result.extend([ch, ch, ch])
                    i += 3
                    in_string = None
                    continue
                result.append(ch)
            elif ch == in_string:
                result.append(ch)
                in_string = None
            else:
                result.append(ch)
        else:
            if ch in ('"', "'"):
                if code[i:i+3] in ('"""', "'''"):
                    in_string = code[i:i+3]
                    result.extend([ch, ch, ch])
                    i += 3
                    continue
                in_string = ch
            result.append(ch)
        i += 1
    return ''.join(result)


def _detect_input_calls(code: str) -> int:
    return len(re.findall(r'\binput\s*\(', code))


def _has_infinite_input_loop(code: str) -> bool:
    has_while = bool(re.search(r'while\s+(True|1)', code))
    has_input = bool(re.search(r'\binput\s*\(', code))
    return has_while and has_input


def _generate_mock_values(code: str) -> list:
    import re as _re
    import random
    values = []
    for match in _re.finditer(r'input\s*\(\s*["\']([^"\']*)["\']', code):
        prompt = match.group(1).lower()
        # Check if wrapped in float() or int()
        start = max(0, match.start() - 20)
        before = code[start:match.start()]
        is_float = 'float(' in before
        is_int = 'int(' in before
        if any(w in prompt for w in ["number", "num", "age", "price", "cost", "sum",
                                      "enter first", "enter second", "value", "width",
                                      "height", "length", "rate", "percent"]):
            if is_float:
                values.append(str(round(random.uniform(1.0, 100.0), 2)))
            elif is_int:
                values.append(str(random.randint(1, 100)))
            else:
                values.append(str(random.randint(1, 100)))
        elif any(w in prompt for w in ["name", "string", "text", "input your"]):
            values.append(random.choice(["alice", "bob", "hello", "test", "demo"]))
        elif any(w in prompt for w in ["yes", "no", "continue", "quit", "exit", "confirm"]):
            values.append(random.choice(["yes", "y", "1"]))
        elif any(w in prompt for w in ["menu", "choice", "option", "select"]):
            values.append(str(random.randint(1, 3)))
        else:
            if is_float:
                values.append(str(round(random.uniform(1.0, 50.0), 2)))
            else:
                values.append(str(random.randint(1, 50)))
    if not values:
        values = [str(random.randint(1, 50)) for _ in range(_detect_input_calls(code))]
    # For while-loop + input() patterns, add extra values then "done" to break
    if _has_infinite_input_loop(code):
        # Add 3-5 numeric values, then "done" to break the loop
        extra = [str(round(random.uniform(1.0, 50.0), 2)) for _ in range(random.randint(3, 5))]
        values = extra + [random.choice(["done", "quit", "exit", "stop", "q"])]
    while len(values) < 20:
        values.append(str(random.randint(1, 50)))
    return values


def _build_input_wrapper(code: str, values: list, filename: str) -> str:
    import base64
    code_b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    values_json = json.dumps(values)
    return f'''import builtins
import base64

_values = {values_json}
_idx = [0]

def _mock_input(prompt=""):
    if prompt:
        print(prompt, end="", flush=True)
    val = _values[_idx[0] % len(_values)]
    _idx[0] += 1
    print(val)
    return val

builtins.input = _mock_input

_code = base64.b64decode("{code_b64}").decode("utf-8")
exec(compile(_code, "{filename}", "exec"))
'''


def _needs_args(code: str) -> bool:
    """Check if code requires CLI arguments (argparse or sys.argv)."""
    import re
    has_argparse = bool(re.search(r'argparse\.ArgumentParser|\.parse_args\(\)', code))
    has_argv = bool(re.search(r'sys\.argv\[\d+\]', code))
    return has_argparse or has_argv


def _generate_cli_args(code: str) -> str:
    """Analyze code to detect arg count/types and generate matching random test values."""
    import re
    import random as _rnd

    has_argparse = bool(re.search(r'argparse\.ArgumentParser|\.parse_args\(\)', code))
    if has_argparse:
        arg_calls = re.findall(
            r'\.add_argument\(\s*["\']([^"\']+)["\']([^)]*)\)', code)
        parts = []
        for name, kwargs in arg_calls:
            kw = {}
            for m in re.finditer(r'(\w+)\s*=\s*([^,\)]+)', kwargs):
                kw[m.group(1)] = m.group(2).strip()

            choices_str = kw.get('choices', '')
            type_name = kw.get('type', '')
            nargs = kw.get('nargs', '')
            has_default = 'default' in kw

            if has_default and nargs != 'required':
                continue

            if name.startswith('-'):
                if choices_str:
                    choices = re.findall(r'["\'](\w+)["\']', choices_str)
                    parts.append(f'{name} {_rnd.choice(choices)}')
                elif nargs and ('+' in nargs or 'REMAINDER' in nargs):
                    n = _rnd.randint(2, 4)
                    if type_name in ('int', 'float'):
                        vals = [str(round(_rnd.uniform(1, 100), 2)) for _ in range(n)]
                    else:
                        vals = [f'val{_+1}' for _ in range(n)]
                    parts.append(f'{name} {" ".join(vals)}')
                elif type_name in ('int', 'float'):
                    val = _rnd.randint(1, 100) if type_name == 'int' else round(_rnd.uniform(1, 100), 2)
                    parts.append(f'{name} {val}')
                else:
                    parts.append(f'{name} test_value')
            else:
                if choices_str:
                    choices = re.findall(r'["\'](\w+)["\']', choices_str)
                    parts.append(_rnd.choice(choices))
                elif nargs and ('+' in nargs):
                    n = _rnd.randint(2, 4)
                    if type_name in ('int', 'float'):
                        vals = [str(round(_rnd.uniform(1, 100), 2)) for _ in range(n)]
                    else:
                        vals = [f'val{_+1}' for _ in range(n)]
                    parts.append(' '.join(vals))
                elif type_name in ('int', 'float'):
                    val = _rnd.randint(1, 100) if type_name == 'int' else round(_rnd.uniform(1, 100), 2)
                    parts.append(str(val))
                elif nargs and ('+' in nargs):
                    n = _rnd.randint(2, 4)
                    vals = [str(round(_rnd.uniform(1, 100), 2)) for _ in range(n)]
                    parts.append(' '.join(vals))
                else:
                    parts.append(str(_rnd.randint(1, 100)))
        if parts:
            return ' '.join(parts)
        return '--operation add --values 5.0 3.0'

    argv_refs = re.findall(r'sys\.argv\[(\d+)\]', code)
    if argv_refs:
        max_idx = max(int(i) for i in argv_refs)
        values = []
        for i in range(1, max_idx + 1):
            # Direct float/int casts
            uses_float = bool(re.search(rf'float\s*\(\s*sys\.argv\[{i}\]', code))
            uses_int = bool(re.search(rf'int\s*\(\s*sys\.argv\[{i}\]', code))

            # Find variable assigned from this argv
            var_match = re.search(rf'(\w+)\s*=\s*sys\.argv\[{i}\]', code)
            var_name = var_match.group(1) if var_match else None

            # Look for if/elif choices via variable
            all_choices = []
            if var_name:
                all_choices = re.findall(
                    rf'(?:if|elif)\s+{var_name}\s*==\s*["\'](.+?)["\']', code)
                all_choices += re.findall(
                    rf'["\'](.+?)["\']\s*==\s*{var_name}', code)
            if not all_choices:
                all_choices = re.findall(
                    rf'(?:if|elif)\s+sys\.argv\[{i}\]\s*==\s*["\'](.+?)["\']', code)
            # in [...] patterns
            if not all_choices and var_name:
                in_match = re.search(
                    rf'{var_name}\s+(?:not\s+)?in\s*\[([^\]]+)\]', code)
                if in_match:
                    all_choices = [c.strip().strip('"\'')
                                   for c in in_match.group(1).split(',')]
            # Dict dispatch: ops = {'add': ..., 'sub': ...} accessed via dict[var]
            if not all_choices and var_name:
                dict_access = re.findall(
                    rf'(\w+)\s*\[\s*{var_name}\s*\]', code)
                for dict_name in dict_access:
                    dict_def = re.search(
                        rf'{dict_name}\s*=\s*\{{([^}}]+)\}}', code)
                    if dict_def:
                        all_choices = re.findall(
                            r'["\'](\w+)["\']\s*:', dict_def.group(1))
                        if all_choices:
                            break

            if all_choices:
                values.append(_rnd.choice(all_choices))
            elif uses_float or (var_name and re.search(
                    rf'float\s*\(\s*{var_name}\b', code)):
                values.append(str(round(_rnd.uniform(1, 100), 2)))
            elif uses_int or (var_name and re.search(
                    rf'int\s*\(\s*{var_name}\b', code)):
                values.append(str(_rnd.randint(1, 100)))
            else:
                values.append(str(round(_rnd.uniform(-50, 50), 2) if i % 2 == 0
                                 else _rnd.randint(1, 50)))
        return ' '.join(values)

    return f'{round(_rnd.uniform(-100, 100), 2)} {round(_rnd.uniform(-100, 100), 2)}'


def run_code(code, language, filename=None):
    """Write code to a temp file, compile if needed, run it.
    Returns (exit_code, stdout, stderr) where stderr contains compiler warnings."""
    ext_map = {
        "python": ".py", "python3": ".py",
        "c": ".c", "cpp": ".cpp", "c++": ".cpp",
        "javascript": ".js", "node": ".js",
        "bash": ".sh", "shell": ".sh",
        "java": ".java",
        "rust": ".rs", "go": ".go",
    }
    lang = language.lower().strip("```")
    ext = ext_map.get(lang, ".txt")
    if not filename:
        filename = f"tmp/run{ext}"

    container = get_container()
    if not container:
        return -1, "", "Container not running."

    exec_command("mkdir -p /workspace/tmp")
    # Fix newlines inside string literals
    if _detect_input_calls(code) > 0:
        code = _escape_code_newlines(code)
    write_file(f"/workspace/{filename}", code)

    prog = filename.rsplit(".", 1)[0]
    compile_cmds = {
        "c":    f"cd /workspace && gcc -Wall -o {prog} {filename} 2>tmp/compile_err.txt",
        "cpp":  f"cd /workspace && g++ -Wall -o {prog} {filename} 2>tmp/compile_err.txt",
        "java": f"cd /workspace && javac {filename} 2>tmp/compile_err.txt",
        "rust": f"cd /workspace && rustc -o {prog} {filename} 2>tmp/compile_err.txt",
    }
    run_cmds = {
        "c":    f"cd /workspace && ./{prog}",
        "cpp":  f"cd /workspace && ./{prog}",
        "python": f"cd /workspace && python3 {filename}",
        "python3": f"cd /workspace && python3 {filename}",
        "javascript": f"cd /workspace && node {filename}",
        "node": f"cd /workspace && node {filename}",
        "bash": f"cd /workspace && bash {filename}",
        "shell": f"cd /workspace && bash {filename}",
        "java": f"cd /workspace && java {os.path.splitext(os.path.basename(filename))[0]}",
        "rust": f"cd /workspace && ./{prog}",
        "go":   f"cd /workspace && go run {filename}",
    }

    if lang not in run_cmds:
        return -1, "", f"Unsupported language: {lang}"

    # For Python with input() calls, use wrapper with mock input
    if lang in ("python", "python3") and _detect_input_calls(code) > 0:
        values = _generate_mock_values(code)
        wrapper = _build_input_wrapper(code, values, filename)
        write_file("/workspace/tmp/_input_wrapper.py", wrapper)
        run_cmd = f"cd /workspace && python3 tmp/_input_wrapper.py"
    elif lang in ("python", "python3") and _needs_args(code):
        # Code uses argparse or sys.argv — provide test arguments
        args = _generate_cli_args(code)
        run_cmd = f"cd /workspace && python3 {filename} {args}"
    else:
        run_cmd = run_cmds[lang]

    warnings = ""
    if lang in compile_cmds:
        code, out = exec_command(compile_cmds[lang], timeout=30)
        if code != 0:
            warn = read_file("/workspace/tmp/compile_err.txt") or out
            return code, out, warn
        warnings = read_file("/workspace/tmp/compile_err.txt") or ""

    exit_code, stdout = exec_command(run_cmd, timeout=30)
    return exit_code, stdout, warnings


if __name__ == "__main__":
    print("Testing Docker environment...")
    container, first_run = ensure_container()
    print(f"Container: {container.short_id}, first_run: {first_run}")
    print(f"Status: {container.status}")

    if first_run:
        print("Waiting for tools to install...")
        time.sleep(5)

    print(f"Container status: {container_status()}")
    code, output = exec_command("gcc --version && python3 --version && node --version")
    print(f"Tools:\n{output[:500]}")
