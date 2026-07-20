#!/usr/bin/env python3
"""WebSocket server for Docker terminal — bridges xterm.js to Docker exec."""

import asyncio
import json
import signal
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import websockets
import docker_env

PORT = 8766
active_sessions = {}


def send_to_terminal(cmd: str) -> bool:
    """Send a command to the active terminal session. Returns True if sent."""
    if not active_sessions:
        return False
    session = next(iter(active_sessions.values()))
    exec_socket = session.get("exec_socket")
    if not exec_socket:
        return False
    try:
        exec_socket._sock.sendall((cmd + "\n").encode("utf-8"))
        return True
    except Exception:
        return False


class TerminalHTTPHandler(BaseHTTPRequestHandler):
    """HTTP endpoint to send commands to the terminal."""

    def do_POST(self):
        if self.path == "/terminal/send":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else ""
            if body:
                ok = send_to_terminal(body)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"sent": ok}).encode())
            else:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


async def handle_terminal(websocket):
    """Handle a terminal WebSocket connection."""
    container = docker_env.get_container()
    if not container or container.status != "running":
        try:
            container, _ = docker_env.ensure_container()
        except Exception as e:
            await websocket.send(json.dumps({"type": "error", "text": str(e)}))
            return

    client = docker_env.get_client()

    exec_instance = client.api.exec_create(
        container.id,
        cmd=["bash", "-l"],
        stdin=True,
        tty=True,
        workdir="/workspace",
    )

    exec_socket = client.api.exec_start(
        exec_instance["Id"],
        socket=True,
        tty=True,
    )

    session_id = id(websocket)
    active_sessions[session_id] = {"exec_socket": exec_socket, "exec_id": exec_instance["Id"]}

    loop = asyncio.get_event_loop()

    async def docker_to_ws():
        try:
            while True:
                data = await loop.run_in_executor(
                    None, lambda: exec_socket._sock.recv(65536)
                )
                if not data:
                    break
                # tty=True means raw output, no stream protocol headers
                await websocket.send(data)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception:
            pass

    async def ws_to_docker():
        try:
            async for message in websocket:
                if isinstance(message, str):
                    try:
                        ctrl = json.loads(message)
                        if ctrl.get("type") == "resize":
                            client.api.exec_resize(
                                exec_instance["Id"],
                                height=ctrl.get("rows", 24),
                                width=ctrl.get("cols", 80),
                            )
                            continue
                    except (json.JSONDecodeError, KeyError):
                        pass
                    message = message.encode("utf-8")
                if isinstance(message, bytes):
                    await loop.run_in_executor(
                        None, lambda m=message: exec_socket._sock.sendall(m)
                    )
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception:
            pass

    try:
        await asyncio.gather(docker_to_ws(), ws_to_docker())
    except Exception:
        pass
    finally:
        active_sessions.pop(session_id, None)
        try:
            exec_socket._sock.close()
        except Exception:
            pass


async def main():
    docker_env.ensure_container()

    # Start HTTP server for terminal commands in a thread
    http_server = HTTPServer(("0.0.0.0", PORT + 1), TerminalHTTPHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    print(f"[WS] Terminal HTTP on http://0.0.0.0:{PORT + 1}")

    async with websockets.serve(
        handle_terminal,
        "0.0.0.0",
        PORT,
        max_size=None,
        ping_interval=None,
    ):
        print(f"[WS] Terminal server running on ws://0.0.0.0:{PORT}")
        await asyncio.Future()


def shutdown(sig, frame):
    print("\n[WS] Shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    asyncio.run(main())
