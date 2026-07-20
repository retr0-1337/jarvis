import os
import json
import uuid
import urllib.parse
import subprocess
import asyncio
import tempfile
import threading
from http.server import HTTPServer, ThreadingHTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
import docker_env

from config import PROJECT_DIR, TRANSCRIPT_FILE, CONV_LOG, CHATS_DIR, ACTIVE_CHAT_FILE

TRANSCRIPT_FILE = str(TRANSCRIPT_FILE)
LOG_FILE = str(CONV_LOG)
PORT = 8765
CHATS_DIR = str(CHATS_DIR)
ACTIVE_CHAT_FILE = str(ACTIVE_CHAT_FILE)
MIC_MUTED_FILE = "/tmp/jarvis_mic_muted"
PROJECT_DIR = str(PROJECT_DIR)
TTS_MUTED_FILE = "/tmp/jarvis_tts_muted"

os.makedirs(CHATS_DIR, exist_ok=True)


def get_active_chat():
    if os.path.exists(ACTIVE_CHAT_FILE):
        with open(ACTIVE_CHAT_FILE) as f:
            cid = f.read().strip()
        if cid and os.path.exists(os.path.join(CHATS_DIR, cid + ".log")):
            return cid
    chats = list_chats()
    if chats:
        cid = chats[0]["id"]
        with open(ACTIVE_CHAT_FILE, "w") as f:
            f.write(cid)
        return cid
    return new_chat()


def new_chat():
    cid = uuid.uuid4().hex[:12]
    path = os.path.join(CHATS_DIR, cid + ".log")
    with open(path, "w") as f:
        pass
    with open(ACTIVE_CHAT_FILE, "w") as f:
        f.write(cid)
    return cid


def list_chats():
    chats = []
    for fn in sorted(os.listdir(CHATS_DIR)):
        if not fn.endswith(".log"):
            continue
        cid = fn[:-4]
        path = os.path.join(CHATS_DIR, fn)
        title = "New Chat"
        msg_count = 0
        mtime = os.path.getmtime(path)
        last_user_msg = ""
        try:
            with open(path) as f:
                for line in f:
                    line = line.rstrip("\n")
                    text = line
                    if len(line) > 12 and line[0] == "[" and line[3] == ":" and line[9] == "]":
                        text = line[10:].lstrip()
                    if text.startswith("[You] "):
                        msg_count += 1
                        last_user_msg = text[6:80]
                    elif text.startswith("[Jarvis] "):
                        msg_count += 1
        except Exception:
            pass
        if last_user_msg:
            title = last_user_msg
        date_str = datetime.fromtimestamp(mtime).strftime("%b %d, %H:%M")
        chats.append({
            "id": cid,
            "title": title,
            "date": date_str,
            "messages": msg_count,
            "mtime": mtime,
        })
    chats.sort(key=lambda c: c["mtime"], reverse=True)
    return chats


def get_active_log():
    cid = get_active_chat()
    return os.path.join(CHATS_DIR, cid + ".log")


def get_branches_file():
    cid = get_active_chat()
    return os.path.join(CHATS_DIR, cid + ".json")


def load_branches():
    bf = get_branches_file()
    if os.path.exists(bf):
        with open(bf) as f:
            return json.load(f)
    return {"messages": [], "branches": {}, "branch_idx": {}, "deleted": []}


def save_branches(data):
    bf = get_branches_file()
    with open(bf, "w") as f:
        json.dump(data, f, indent=2)


def parse_log_to_branches(log_path):
    """Parse flat log into branch structure on first load"""
    messages = []
    if not os.path.exists(log_path):
        return messages
    with open(log_path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            ts = ""
            text = line
            if len(line) > 12 and line[0] == "[" and line[3] == ":" and line[9] == "]":
                ts = line[1:9]
                text = line[10:].lstrip()
            if text.startswith("[You] "):
                messages.append({"sender": "You", "userText": text[6:], "userTs": ts, "responses": []})
            elif text.startswith("[Jarvis] "):
                inner = text[9:]
                if "Jarvis restarted" in inner or "Resuming previous chat" in inner:
                    continue
                if not messages:
                    messages.append({"sender": "You", "userText": "", "userTs": "", "responses": []})
                messages[-1]["responses"].append({"text": inner, "ts": ts})
            elif messages and messages[-1]["responses"]:
                messages[-1]["responses"][-1]["text"] += "\n" + text
    return messages


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
      try:
        self._do_GET_inner()
      except (BrokenPipeError, ConnectionResetError):
        pass
      except Exception:
        try:
          self.send_response(500)
          self.end_headers()
          self.wfile.write(b'Internal Server Error')
        except Exception:
          pass

    def _do_GET_inner(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            bd = load_branches()
            log = get_active_log()
            # JSON is source of truth for branches. Log is source of truth for message text.
            if not bd["messages"]:
                bd["messages"] = parse_log_to_branches(log)
                save_branches(bd)
            else:
                # Sync: add any remaining log messages not yet in JSON
                log_msgs = parse_log_to_branches(log)
                deleted_texts = set(bd.get("deleted", []))
                if len(log_msgs) > len(bd["messages"]):
                    new_msgs = log_msgs[len(bd["messages"]):]
                    for nm in new_msgs:
                        if nm.get("responses"):
                            nm["responses"] = [r for r in nm["responses"]
                                                if r["text"] not in deleted_texts]
                    bd["messages"].extend(new_msgs)
                    save_branches(bd)
                # Update userText from log for messages that have empty text in JSON
                for i, m in enumerate(bd["messages"]):
                    if i < len(log_msgs) and not m.get("userText") and log_msgs[i].get("userText"):
                        m["userText"] = log_msgs[i]["userText"]
                        m["userTs"] = log_msgs[i].get("userTs", "")
                # Fill responses from log for messages with NO responses and NO old_responses
                deleted_texts = set(bd.get("deleted", []))
                for i, m in enumerate(bd["messages"]):
                    if i < len(log_msgs):
                        if not m.get("responses") and not m.get("old_responses") and log_msgs[i].get("responses"):
                            m["responses"] = [r for r in log_msgs[i]["responses"]
                                               if r["text"] not in deleted_texts]
                save_branches(bd)
            msgs = []
            for i, m in enumerate(bd["messages"]):
                bi = bd["branch_idx"].get(str(i), 0)
                # Build full response list: old_responses (if any) + new responses
                old_resp = m.get("old_responses", [])
                new_resp = m.get("responses", [])
                resps = old_resp + new_resp
                # Add user message
                msgs.append({
                    "sender": "You",
                    "text": m.get("userText", ""),
                    "ts": m.get("userTs", ""),
                    "branchCount": 1,
                    "branchIdx": 0,
                    "msgIdx": i,
                })
                # Add Jarvis response (current branch)
                if resps:
                    ri = min(bi, len(resps)-1)
                    msgs.append({
                        "sender": "Jarvis",
                        "text": resps[ri]["text"],
                        "ts": resps[ri]["ts"],
                        "branchCount": len(resps),
                        "branchIdx": ri,
                        "msgIdx": i,
                    })
            self.wfile.write(json.dumps({"messages": msgs}).encode())

        elif path == "/think":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            thinking_file = "/tmp/jarvis_thinking.txt"
            if os.path.exists(thinking_file):
                with open(thinking_file, "r") as f:
                    self.wfile.write(f.read().encode())
            else:
                self.wfile.write(b"")

        elif path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            thinking = "0"
            try:
                with open("/tmp/jarvis_status.txt") as f:
                    thinking = f.read().strip()
            except Exception:
                pass
            self.wfile.write(thinking.encode())

        elif path == "/sysinfo":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            info = {}
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            info["memTotal"] = int(line.split()[1]) // 1024
                        elif line.startswith("MemAvailable:"):
                            info["memAvail"] = int(line.split()[1]) // 1024
                info["memUsed"] = info["memTotal"] - info["memAvail"]
            except Exception:
                info = {"memTotal": 0, "memUsed": 0, "memAvail": 0}
            try:
                with open("/tmp/jarvis_status.txt") as f:
                    info["thinking"] = f.read().strip() == "1"
            except Exception:
                info["thinking"] = False
            try:
                with open("/tmp/jarvis_thinking.txt") as f:
                    info["task"] = f.read().strip()[:200]
            except Exception:
                info["task"] = ""
            procs = []
            import subprocess as _sp
            try:
                r = _sp.run(["pgrep", "-af", "jarv2|webui|ollama|auto_responder"],
                            capture_output=True, text=True, timeout=3)
                for line in r.stdout.strip().splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        pid = parts[0]
                        cmd = parts[1][:80]
                        try:
                            with open(f"/proc/{pid}/status") as sf:
                                for sl in sf:
                                    if sl.startswith("VmRSS:"):
                                        rss = int(sl.split()[1]) // 1024
                                        procs.append({"pid": pid, "rss": rss, "cmd": cmd})
                                        break
                        except Exception:
                            procs.append({"pid": pid, "rss": 0, "cmd": cmd})
            except Exception:
                pass
            info["procs"] = procs
            self.wfile.write(json.dumps(info).encode())

        elif path == "/stop":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                open("/tmp/jarvis_status.txt", "w").close()
                with open("/tmp/jarvis_status.txt", "w") as f:
                    f.write("0")
                open("/tmp/jarvis_thinking.txt", "w").close()
                # Signal pipeline to abort
                open("/tmp/jarvis_pipeline_abort", "w").close()
                # Stop TTS in jarv2 via SIGUSR1
                r2 = subprocess.run(["pgrep", "-f", "jarv2.py"],
                                   capture_output=True, text=True, timeout=3)
                for pid in r2.stdout.strip().splitlines():
                    try:
                        import signal as _sig
                        _sig.signal(int(pid), _sig.SIGUSR1)
                    except Exception:
                        pass
                # Kill ask.py processes (pipeline running as child of auto_responder)
                r_ask = subprocess.run(["pgrep", "-f", "ask\\.py"],
                                      capture_output=True, text=True, timeout=3)
                for pid in r_ask.stdout.strip().splitlines():
                    try:
                        import signal as _sig
                        _sig.signal(int(pid), _sig.SIGTERM)
                    except Exception:
                        pass
                # Kill auto_responder and its children
                import signal as _sig
                r = subprocess.run(["pgrep", "-f", "auto_responder"],
                                   capture_output=True, text=True, timeout=3)
                for pid in r.stdout.strip().splitlines():
                    try:
                        # Kill children first (ask.py, pipeline)
                        children = subprocess.run(["pgrep", "-P", pid.strip()],
                                                  capture_output=True, text=True, timeout=3)
                        for cpid in children.stdout.strip().splitlines():
                            try:
                                _sig.signal(int(cpid), _sig.SIGTERM)
                            except Exception:
                                pass
                        _sig.signal(int(pid), _sig.SIGTERM)
                    except Exception:
                        pass
                self.wfile.write(b"ok")
            except Exception:
                self.wfile.write(b"ok")

        elif path == "/send":
            text = params.get("text", [""])[0]
            if text:
                # Collapse multi-line text into single line for transcript (auto_responder reads tail -1)
                text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                ts = datetime.now().strftime("%H:%M:%S")
                log = get_active_log()
                with open(TRANSCRIPT_FILE, "a") as f:
                    f.write(f"[{ts}] [text] {text}\n")
                with open(log, "a") as f:
                    f.write(f"[{ts}] [You] {text}\n")
                # Add user message to JSON so write_response appends to the right message
                try:
                    bd = load_branches()
                    bd["messages"].append({
                        "sender": "You",
                        "userText": text,
                        "userTs": ts,
                        "responses": []
                    })
                    save_branches(bd)
                except Exception:
                    pass
                with open("/tmp/jarvis_status.txt", "w") as f:
                    f.write("1")
                open("/tmp/jarvis_thinking.txt", "w").close()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        elif path == "/mic":
            muted = params.get("muted", ["0"])[0]
            if muted == "1":
                open(MIC_MUTED_FILE, "w").close()
            else:
                if os.path.exists(MIC_MUTED_FILE):
                    os.remove(MIC_MUTED_FILE)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"muted": muted == "1"}).encode())

        elif path == "/micstatus":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            muted = "1" if os.path.exists(MIC_MUTED_FILE) else "0"
            self.wfile.write(muted.encode())

        elif path == "/tts":
            muted = params.get("muted", ["0"])[0]
            if muted == "1":
                open(TTS_MUTED_FILE, "w").close()
            else:
                if os.path.exists(TTS_MUTED_FILE):
                    os.remove(TTS_MUTED_FILE)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"muted": muted == "1"}).encode())

        elif path == "/mic/level":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"level": 0}).encode())

        elif path == "/ttsstatus":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            muted = "1" if os.path.exists(TTS_MUTED_FILE) else "0"
            self.wfile.write(muted.encode())

        elif path == "/settings":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            import config
            self.wfile.write(json.dumps(config.load_config()).encode())

        elif path == "/settings/save":
            import config
            cfg = config.load_config()
            for key in ["mic_device", "tts_voice", "ollama_model", "whisper_model",
                         "energy_threshold", "no_speech_threshold", "min_segment_duration",
                         "vad_aggressiveness", "tts_speed", "num_ctx", "auto_start",
                         "preview_text"]:
                if key in params:
                    val = params[key][0]
                    if key in ("energy_threshold", "vad_aggressiveness", "num_ctx"):
                        try: val = int(val)
                        except: pass
                    elif key in ("no_speech_threshold", "min_segment_duration", "tts_speed"):
                        try: val = float(val)
                        except: pass
                    elif key == "auto_start":
                        val = val in ("true", "1", "on", "yes")
                    cfg[key] = val
            config.save_config(cfg)
            if "auto_start" in params:
                action = "enable" if cfg["auto_start"] else "disable"
                subprocess.run(["systemctl", "--user", action, "jarvis.service"],
                               capture_output=True, timeout=5)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "settings": cfg}).encode())

        elif path == "/settings/mics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                import speech_recognition as sr
                mics = sr.Microphone.list_microphone_names()
            except Exception:
                mics = []
            default_mic = ""
            # Prefer "pipewire" or "default" virtual devices (hardware devices crash PyAudio on PipeWire)
            for pref in ["pipewire", "default"]:
                if pref in mics:
                    default_mic = pref
                    break
            if not default_mic:
                try:
                    r = subprocess.run(["pactl", "get-default-source"], capture_output=True, text=True, timeout=3)
                    default_name = r.stdout.strip()
                    if default_name:
                        r2 = subprocess.run(["pactl", "list", "sources"], capture_output=True, text=True, timeout=3)
                        desc = ""
                        in_block = False
                        for line in r2.stdout.splitlines():
                            if line.strip().startswith("Name:") and default_name in line:
                                in_block = True
                            elif in_block and line.strip().startswith("Description:"):
                                desc = line.split(":",1)[1].strip()
                                break
                        if desc:
                            for m in mics:
                                if desc == m or desc in m or m in desc:
                                    default_mic = m
                                    break
                except Exception:
                    pass
            if not default_mic and mics:
                default_mic = mics[0]
            self.wfile.write(json.dumps({"mics": mics, "default": default_mic}).encode())

        elif path == "/settings/voices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                import asyncio, edge_tts
                voices = asyncio.run(edge_tts.list_voices())
                en_voices = [{"name": v["ShortName"], "gender": v["Gender"], "locale": v["Locale"]}
                             for v in voices if v["Locale"].startswith("en-")]
            except Exception:
                en_voices = []
            self.wfile.write(json.dumps({"voices": en_voices}).encode())

        elif path == "/tts/preview":
            voice = params.get("voice", ["en-US-SteffanNeural"])[0]
            text = params.get("text", ["Hello, I'm Jarvis. How can I help you today?"])[0]
            speed = float(params.get("speed", ["1.0"])[0])
            rate = f"+{int((speed - 1) * 100)}%" if speed >= 1.0 else f"{int((speed - 1) * 100)}%"
            self.send_response(200)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            tmp = tempfile.mktemp(suffix=".mp3")
            try:
                venv_python = os.path.join(PROJECT_DIR, "venv/bin/python")
                script = (
                    "import edge_tts,asyncio,sys;"
                    "asyncio.run(edge_tts.Communicate(sys.argv[1],sys.argv[2],rate=sys.argv[3]).save(sys.argv[4]))"
                )
                subprocess.run([venv_python, "-c", script, text, voice, rate, tmp],
                               timeout=12, capture_output=True)
                if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
                    with open(tmp, "rb") as f:
                        self.wfile.write(f.read())
            except Exception:
                pass
            finally:
                try: os.unlink(tmp)
                except: pass

        elif path == "/settings/models":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                from urllib.request import urlopen
                req = urlopen("http://localhost:11434/api/tags", timeout=3)
                data = json.loads(req.read())
                models = [m["name"] for m in data.get("models", []) if "embed" not in m["name"].lower()]
            except Exception:
                models = []
            self.wfile.write(json.dumps({"models": models}).encode())

        elif path == "/chats":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            chats = list_chats()
            active = get_active_chat()
            self.wfile.write(json.dumps({"chats": chats, "active": active}).encode())

        elif path == "/newchat":
            cid = new_chat()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": cid}).encode())

        elif path == "/switchchat":
            cid = params.get("id", [""])[0]
            if cid and os.path.exists(os.path.join(CHATS_DIR, cid + ".log")):
                with open(ACTIVE_CHAT_FILE, "w") as f:
                    f.write(cid)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')
            else:
                self.send_response(404)
                self.end_headers()

        elif path == "/deletechat":
            cid = params.get("id", [""])[0]
            if cid:
                for ext in [".log", ".json"]:
                    p = os.path.join(CHATS_DIR, cid + ext)
                    if os.path.exists(p):
                        os.remove(p)
                if os.path.exists(ACTIVE_CHAT_FILE):
                    with open(ACTIVE_CHAT_FILE) as f:
                        if f.read().strip() == cid:
                            chats = list_chats()
                            if chats:
                                with open(ACTIVE_CHAT_FILE, "w") as f2:
                                    f2.write(chats[0]["id"])
                            else:
                                os.remove(ACTIVE_CHAT_FILE)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        elif path == "/editmsg":
            idx = params.get("idx", ["0"])[0]
            new_text = params.get("text", [""])[0]
            try:
                idx = int(idx)
            except:
                idx = 0
            bd = load_branches()
            if not bd["messages"]:
                log = get_active_log()
                bd["messages"] = parse_log_to_branches(log)
            if idx < len(bd["messages"]):
                ts_now = datetime.now().strftime("%H:%M:%S")
                msg = bd["messages"][idx]
                if new_text:
                    old_resp = msg.get("old_responses", [])
                    cur_resp = msg.get("responses", [])
                    all_resp = old_resp + cur_resp
                    if all_resp:
                        cur_bi = min(bd["branch_idx"].get(str(idx), 0), len(all_resp)-1)
                        msg["old_responses"] = [all_resp[cur_bi]]
                    else:
                        msg["old_responses"] = []
                    msg["userText"] = new_text
                    msg["userTs"] = ts_now
                    msg["responses"] = []
                    bd["branch_idx"][str(idx)] = 0
                    save_branches(bd)
                    with open("/tmp/jarvis_edit_idx", "w") as f:
                        f.write(str(idx))
                    with open(TRANSCRIPT_FILE, "a") as f:
                        f.write(f"[{ts_now}] [text] {new_text}\n")
                    log = get_active_log()
                    with open(log, "a") as f:
                        f.write(f"[{ts_now}] [You] {new_text}\n")
                    with open("/tmp/jarvis_status.txt", "w") as f:
                        f.write("1")
                    open("/tmp/jarvis_thinking.txt", "w").close()
                else:
                    # Deletion
                    bd["messages"].pop(idx)
                    # Re-index branch_idx
                    new_bi = {}
                    for k, v in bd["branch_idx"].items():
                        ki = int(k)
                        if ki < idx:
                            new_bi[str(ki)] = v
                        elif ki > idx:
                            new_bi[str(ki - 1)] = v
                    bd["branch_idx"] = new_bi
                    save_branches(bd)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        elif path == "/switchbranch":
            idx = params.get("idx", ["0"])[0]
            branch = params.get("branch", ["0"])[0]
            try:
                idx = int(idx)
                branch = int(branch)
            except:
                idx = 0
                branch = 0
            bd = load_branches()
            if idx < len(bd["messages"]):
                max_branch = len(bd["messages"][idx]["responses"]) - 1
                bd["branch_idx"][str(idx)] = max(0, min(branch, max_branch))
                save_branches(bd)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        elif path == "/deletebranch":
            idx = params.get("idx", ["0"])[0]
            branch = params.get("branch", ["0"])[0]
            try:
                idx = int(idx)
                branch = int(branch)
            except:
                idx = 0
                branch = 0
            bd = load_branches()
            if idx < len(bd["messages"]):
                resps = bd["messages"][idx]["responses"]
                if len(resps) > 1 and 0 <= branch < len(resps):
                    deleted_text = resps[branch]["text"]
                    if "deleted" not in bd:
                        bd["deleted"] = []
                    bd["deleted"].append(deleted_text)
                    del resps[branch]
                    cur = bd["branch_idx"].get(str(idx), 0)
                    if cur >= len(resps):
                        bd["branch_idx"][str(idx)] = len(resps) - 1
                    elif cur > branch:
                        bd["branch_idx"][str(idx)] = cur - 1
                    save_branches(bd)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        elif path == "/container/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                status = docker_env.container_status()
            except Exception as e:
                status = {"exists": False, "status": "error", "error": str(e), "tools_ready": False}
            self.wfile.write(json.dumps(status).encode())

        elif path == "/container/start":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                container, first_run = docker_env.ensure_container()
                self.wfile.write(json.dumps({"ok": True, "id": container.short_id, "first_run": first_run}).encode())
            except Exception as e:
                self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode())

        elif path == "/exec":
            # POST via query param for simplicity (GET server)
            cmd = params.get("cmd", [""])[0]
            workdir = params.get("workdir", ["/workspace"])[0]
            if cmd:
                try:
                    exit_code, output = docker_env.exec_command(cmd, workdir=workdir)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"code": exit_code, "output": output}).encode())
                except Exception as e:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"code": -1, "output": str(e)}).encode())
            else:
                self.send_response(400)
                self.end_headers()

        elif path == "/files":
            fpath = params.get("path", ["/workspace"])[0]
            try:
                entries = docker_env.list_files(fpath)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(json.dumps({"entries": entries, "path": fpath}).encode())
            except Exception as e:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"entries": [], "path": fpath, "error": str(e)}).encode())

        elif path == "/files/read":
            fpath = params.get("path", [""])[0]
            if fpath:
                content = docker_env.read_file(fpath)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"content": content or "", "path": fpath}).encode())
            else:
                self.send_response(400)
                self.end_headers()

        elif path == "/run":
            code = params.get("code", [""])[0]
            lang = params.get("lang", ["python"])[0]
            if code:
                import urllib.parse as _up
                code = _up.unquote(code)
                try:
                    exit_code, output, warnings = docker_env.run_code(code, lang)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"code": exit_code, "output": output, "warnings": warnings}).encode())
                except Exception as e:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"code": -1, "output": str(e), "warnings": ""}).encode())
            else:
                self.send_response(400)
                self.end_headers()

        elif path == "/autofix":
            text = params.get("text", [""])[0]
            if text:
                import urllib.parse as _up
                text = _up.unquote(text)
                ts = datetime.now().strftime("%H:%M:%S")
                try:
                    import subprocess as _sp
                    # Get active chat ID for pipeline abort check
                    _chat_id = ""
                    if os.path.exists(ACTIVE_CHAT_FILE):
                        with open(ACTIVE_CHAT_FILE) as _f:
                            _chat_id = _f.read().strip()
                    result = _sp.run(
                        [os.path.join(PROJECT_DIR, "venv/bin/python"),
                         os.path.join(PROJECT_DIR, "ask.py"), text,
                         "--source", "text", "--chat-id", _chat_id],
                        capture_output=True, text=True, timeout=130,
                        cwd=PROJECT_DIR,
                        env={**os.environ, "PYTHONPATH": PROJECT_DIR}
                    )
                    response_text = result.stdout.strip() or "I couldn't generate a fix."
                except Exception as e:
                    response_text = f"Error generating fix: {e}"
                bd = load_branches()
                if bd["messages"]:
                    msg = bd["messages"][-1]
                    msg.setdefault("responses", []).append({"text": response_text, "ts": ts})
                    save_branches(bd)
                log = get_active_log()
                with open(log, "a") as f:
                    f.write(f"[{ts}] [Jarvis] {response_text}\n")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "response": response_text[:200]}).encode())
            else:
                self.send_response(400)
                self.end_headers()

        elif path == "/pipeline":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                from pipeline import get_pipeline_status
                status = get_pipeline_status()
                if not status or status.get("status") in ("finished", "aborted"):
                    status = {"status": "idle"}
                self.wfile.write(json.dumps(status).encode())
            except Exception:
                self.wfile.write(b'{"status": "idle"}')

        elif path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(build_html().encode())

        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass


def build_html():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<title>Jarvis</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#212121;--sidebar:#171717;--surface:#2f2f2f;--surface2:#383838;--border:#3c3c3c;--text:#e3e3e3;--text2:#b4b4b4;--text3:#8e8e8e;--muted:#666;--accent:#8b5cf6;--accent2:#a78bfa;--you-bg:#2f2f2f;--jarvis-bg:#2f2f2f;--code-bg:#1a1a2e;--code-header:#16213e;--radius:12px;--font:'Inter',system-ui,-apple-system,sans-serif;--mono:'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
body{font-family:var(--font);background:var(--bg);color:var(--text);display:flex;height:100vh;overflow:hidden}

#sidebar{width:260px;background:var(--sidebar);display:flex;flex-direction:column;border-right:1px solid var(--border);flex-shrink:0;transition:margin-left .3s ease,opacity .2s}
#sidebar.collapsed{margin-left:-260px;opacity:0;pointer-events:none}
#sidebar-header{padding:12px;display:flex;gap:8px;align-items:center;border-bottom:1px solid var(--border)}
#new-chat-btn{flex:1;display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:13px;font-family:var(--font);cursor:pointer;transition:background .15s}
#new-chat-btn:hover{background:var(--surface2)}
#new-chat-btn svg{width:16px;height:16px;stroke:var(--text2);flex-shrink:0}
#settings-btn{width:36px;height:36px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background .15s;flex-shrink:0}
#settings-btn:hover{background:var(--surface2)}
#settings-btn svg{width:16px;height:16px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--sidebar);border:1px solid var(--border);border-radius:16px;width:520px;max-height:80vh;overflow-y:auto;padding:24px}
.modal h2{font-size:18px;margin-bottom:16px;color:var(--text)}
.modal h3{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3);margin:16px 0 8px}
.modal label{display:block;font-size:13px;color:var(--text2);margin-bottom:4px}
.modal select,.modal input[type="number"],.modal input[type="text"]{width:100%;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;font-family:var(--font);outline:none;margin-bottom:12px}
.modal select:focus,.modal input:focus{border-color:var(--accent)}
.modal input[type="range"]{width:100%;margin-bottom:4px;accent-color:var(--accent)}
.modal .range-row{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.modal .range-val{font-size:12px;color:var(--text3);min-width:36px;text-align:right}
.modal .toggle-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.modal .toggle-row label{margin-bottom:0}
.modal .toggle{position:relative;width:40px;height:22px;cursor:pointer}
.modal .toggle input{opacity:0;width:0;height:0}
.modal .toggle .slider{position:absolute;inset:0;background:var(--surface2);border-radius:11px;transition:background .2s}
.modal .toggle .slider:before{content:'';position:absolute;width:16px;height:16px;left:3px;top:3px;background:var(--text3);border-radius:50%;transition:transform .2s,background .2s}
.modal .toggle input:checked+.slider{background:var(--accent)}
.modal .toggle input:checked+.slider:before{transform:translateX(18px);background:#fff}
.modal .preview-row{display:flex;gap:6px;margin-bottom:12px;align-items:center}
.modal .preview-row input[type=text]{flex:1;padding:6px 10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:var(--font)}
.btn-preview{padding:6px 12px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-family:var(--font);font-weight:500;background:var(--accent);color:#fff;transition:all .15s;white-space:nowrap}
.btn-preview:hover{opacity:.85}
.btn-preview:disabled{opacity:.5;cursor:default}
.btn-reset{background:var(--surface);color:var(--text2);border:1px solid var(--border)}
.btn-reset:hover{background:var(--surface2)}
.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
.modal-actions button{padding:8px 20px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-family:var(--font);font-weight:500;transition:all .15s}
.modal-actions .btn-save{background:var(--accent);color:#fff}
.modal-actions .btn-save:hover{opacity:.9}
.modal-actions .btn-cancel{background:var(--surface);color:var(--text2);border:1px solid var(--border)}
.modal-actions .btn-cancel:hover{background:var(--surface2)}
#chat-list{flex:1;overflow-y:auto;padding:8px}
#chat-list::-webkit-scrollbar{width:4px}
#chat-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.chat-item{padding:10px 12px;border-radius:8px;cursor:pointer;display:flex;align-items:center;gap:8px;transition:background .1s;margin-bottom:2px}
.chat-item:hover{background:var(--surface)}
.chat-item.active{background:var(--surface2)}
.chat-item .chat-icon{width:16px;height:16px;stroke:var(--text3);flex-shrink:0}
.chat-item .chat-title{flex:1;font-size:13px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chat-item.active .chat-title{color:var(--text)}
.chat-item .chat-info{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
.chat-item .chat-date{font-size:11px;color:var(--text3)}
.chat-item .chat-del{width:24px;height:24px;visibility:hidden;display:flex;align-items:center;justify-content:center;border-radius:4px;color:var(--text3);font-size:16px;cursor:pointer;flex-shrink:0}
.chat-item:hover .chat-del{visibility:visible}
.chat-item .chat-del:hover{background:#e53e3e;color:#fff}
#sidebar-footer{padding:12px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px}
.sidebar-btn{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--text2);transition:background .15s;border:none;background:none;width:100%;font-family:var(--font);text-align:left}
.sidebar-btn:hover{background:var(--surface)}
.sidebar-btn svg{width:16px;height:16px;flex-shrink:0}
.sidebar-btn.danger{color:#e53e3e}
.sidebar-btn.danger:hover{background:rgba(229,62,62,.15)}
#mic-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
#mic-dot.on{background:#48bb78;box-shadow:0 0 6px #48bb78}
#mic-dot.off{background:#e53e3e;box-shadow:0 0 6px #e53e3e}
#mic-level-wrap{display:flex;align-items:stretch;gap:0;margin-left:6px;height:22px;position:relative}
#mic-level{width:6px;background:rgba(255,255,255,.08);border-radius:3px;position:relative;overflow:visible}
#mic-level-bar{position:absolute;bottom:0;width:100%;background:#48bb78;border-radius:3px;transition:height .1s,background .15s}
#mic-threshold{position:absolute;left:-2px;width:10px;height:2px;background:#ecc94b;border-radius:1px;z-index:1}
#tts-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
#tts-dot.on{background:#48bb78;box-shadow:0 0 6px #48bb78}
#tts-dot.off{background:#e53e3e;box-shadow:0 0 6px #e53e3e}

#main{flex:1;display:flex;flex-direction:column;min-width:0}
#topbar{height:48px;display:flex;align-items:center;padding:0 16px;border-bottom:1px solid var(--border);gap:12px;flex-shrink:0}
#menu-btn{width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:8px;cursor:pointer;color:var(--text2);transition:background .15s}
#menu-btn:hover{background:var(--surface)}
#menu-btn svg{width:20px;height:20px}
#top-title{font-size:15px;font-weight:500;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#status-pill{font-size:11px;padding:3px 10px;border-radius:20px;font-weight:500;transition:all .3s;cursor:pointer;border:none;position:relative}
#status-pill.idle{background:rgba(72,187,120,.15);color:#48bb78}
#status-pill.thinking{background:rgba(139,92,246,.2);color:var(--accent2)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
#status-pill.thinking{animation:pulse 1.5s infinite}
#sys-popup{position:fixed;top:48px;right:16px;width:300px;background:var(--sidebar);border:1px solid var(--border);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.4);z-index:999;display:none;padding:16px;font-size:13px;color:var(--text)}
#sys-popup.open{display:block}
#sys-popup h3{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3);margin:0 0 10px}
.sys-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)}
.sys-row:last-child{border-bottom:none}
.sys-label{color:var(--text2);font-size:12px}
.sys-val{font-size:13px;font-weight:500}
.sys-bar{height:4px;border-radius:2px;background:var(--surface2);overflow:hidden;margin-top:4px}
.sys-bar-fill{height:100%;border-radius:2px;transition:width .3s}
.sys-bar-fill.ok{background:#48bb78}
.sys-bar-fill.warn{background:#ed8936}
.sys-bar-fill.danger{background:#e53e3e}
#sys-procs{margin-top:8px;max-height:120px;overflow-y:auto}
.sys-proc{font-size:11px;color:var(--text3);padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05);display:flex;justify-content:space-between}
.sys-proc:last-child{border-bottom:none}
.sys-proc-rss{color:var(--text2);white-space:nowrap}
#sys-stop{width:100%;margin-top:10px;padding:6px;border-radius:8px;border:1px solid #e53e3e;background:rgba(229,62,62,.1);color:#e53e3e;font-size:12px;font-weight:500;cursor:pointer;transition:background .15s}
#sys-stop:hover{background:rgba(229,62,62,.25)}

#chat-area{flex:1;overflow-y:auto;padding:0}
#chat-area::-webkit-scrollbar{width:6px}
#chat-area::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
#chat-inner{max-width:780px;margin:0 auto;padding:24px 20px;display:flex;flex-direction:column;gap:0}

.msg{padding:20px 0;border-bottom:1px solid var(--border);position:relative;width:100%}
.msg:last-child{border-bottom:none}
.msg-you{display:flex;flex-direction:column;align-items:flex-end;justify-content:flex-end;width:100%}
.msg-you .msg-avatar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-direction:row-reverse}
.msg-jarvis .msg-avatar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.msg-avatar{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;flex-shrink:0}
.msg-you .msg-avatar{background:#3b82f6;color:#fff}
.msg-jarvis .msg-avatar{background:var(--accent);color:#fff}
.msg-sender{font-size:13px;font-weight:600;color:var(--text)}
.msg-you .msg-body{font-size:14px;line-height:1.7;color:var(--text2);max-width:70%;background:var(--surface);padding:12px 16px;border-radius:16px 16px 4px 16px;text-align:right;align-self:flex-end}
.msg-jarvis .msg-body{font-size:14px;line-height:1.7;color:var(--text);padding-left:38px}
.msg-body p{margin:4px 0}
.msg-body strong{color:var(--accent);font-weight:600}
.msg-body em{color:var(--text2);font-style:italic}
.msg-body strong em{color:var(--accent);font-weight:600;font-style:italic}
.msg-edit{position:absolute;top:20px;right:8px;opacity:0;transition:opacity .15s;display:flex;gap:4px}
.msg:hover .msg-edit{opacity:1}
.msg-you .msg-edit{right:auto;left:8px}
.msg-edit button{width:28px;height:28px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;transition:all .15s}
.msg-edit button:hover{background:var(--surface2);color:var(--text)}
.msg-edit .edit-del:hover{background:rgba(229,62,62,.15);color:#e53e3e;border-color:rgba(229,62,62,.3)}
.msg-edit-from{opacity:0;transition:opacity .15s}
.msg:hover .msg-edit-from{opacity:1}
.msg-edit-from button{font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;transition:all .15s}
.msg-edit-from button:hover{background:var(--surface2);color:var(--text)}
.branch-nav{display:inline-flex;align-items:center;gap:4px;margin-right:6px}
.branch-nav button{width:22px;height:22px;border-radius:50%;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;font-size:11px;display:flex;align-items:center;justify-content:center;transition:all .15s}
.branch-nav button:hover:not(:disabled){background:var(--accent);color:#fff;border-color:var(--accent)}
.branch-nav button:disabled{opacity:.3;cursor:default}
.branch-nav span{font-size:11px;color:var(--text3);min-width:30px;text-align:center}
.branch-del{color:var(--text3)!important;font-size:13px!important;width:18px!important;height:18px!important;opacity:.5;border:none!important;background:none!important}
.branch-del:hover{color:#e53e3e!important;opacity:1;background:none!important;border:none!important}
.edit-inline{margin:8px 0 4px;padding-left:38px}
.msg-you .edit-inline{padding-left:0;padding-right:0}
.edit-inline textarea{width:100%;background:var(--surface);border:1px solid var(--accent);border-radius:8px;color:var(--text);font-size:14px;font-family:var(--font);padding:10px 12px;outline:none;resize:none;line-height:1.5}
.edit-inline .edit-actions{display:flex;gap:6px;margin-top:6px;justify-content:flex-end}
.edit-inline .edit-actions button{padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-family:var(--font);font-weight:500;transition:all .15s}
.edit-inline .edit-save{background:var(--accent);color:#fff}
.edit-inline .edit-save:hover{background:var(--accent2)}
.edit-inline .edit-cancel{background:var(--surface);color:var(--text2);border:1px solid var(--border)}
.edit-inline .edit-cancel:hover{background:var(--surface2)}

.msg .thoughts{margin:8px 0 4px;margin-left:38px;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;cursor:pointer;user-select:none}
.msg .thoughts .thought-header{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);font-size:12px;color:var(--text3);transition:background .15s}
.msg .thoughts .thought-header:hover{background:var(--surface2)}
.msg .thoughts .thought-header .dots{display:inline-flex;gap:3px}
.msg .thoughts .thought-header .dots span{width:4px;height:4px;background:var(--accent2);border-radius:50%;animation:bounce 1.4s infinite both}
.msg .thoughts .thought-header .dots span:nth-child(2){animation-delay:.2s}
.msg .thoughts .thought-header .dots span:nth-child(3){animation-delay:.4s}
@keyframes bounce{0%,80%,100%{transform:scale(0)}40%{transform:scale(1)}}
.msg .thoughts .thought-header .arrow{margin-left:auto;font-size:10px;color:var(--text3)}
.msg .thoughts .thought-body{display:none;padding:10px 12px;font-size:12px;color:var(--text3);line-height:1.6;word-break:break-word;max-height:300px;overflow-y:auto;white-space:pre-wrap}
.msg .thoughts .thought-body.open{display:block}

.code-block{margin:12px 0;border-radius:var(--radius);overflow:hidden;border:1px solid var(--border)}
.code-block-header{display:flex;align-items:center;justify-content:space-between;padding:6px 12px;background:var(--code-header);font-size:12px;font-family:var(--mono)}
.code-block-lang{color:var(--accent2);font-weight:500}
.code-block-copy{background:none;border:1px solid var(--border);color:var(--text3);padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-family:var(--font);transition:all .15s}
.code-block-copy:hover{background:var(--surface);color:var(--text)}
.code-block-copy.copied{border-color:#48bb78;color:#48bb78}
.code-block-file{color:var(--text3);font-size:11px;font-family:var(--mono);margin-left:8px;opacity:.7}
.code-block-run{background:rgba(72,187,120,.1);border:1px solid rgba(72,187,120,.3);color:#48bb78;padding:2px 8px;border-radius:4px;font-size:10px;font-family:var(--mono);margin-top:2px;display:inline-block;white-space:nowrap}
.code-block pre{background:#0d1117;padding:8px 0 8px 0;overflow-x:auto;margin:0;display:flex}
.code-block code{font-family:var(--mono);font-size:13px;line-height:.55;color:#e2e8f0;counter-reset:line;display:block;flex:1;min-width:0}
.code-block-output{border:1px solid rgba(72,187,120,.4);background:rgba(72,187,120,.06)}
.code-block-output .code-block-header{background:rgba(72,187,120,.12);border-bottom:1px solid rgba(72,187,120,.3)}
.code-block-test{border:1px solid rgba(236,201,75,.4);background:rgba(236,201,75,.06)}
.code-block-test .code-block-header{background:rgba(236,201,75,.12);border-bottom:1px solid rgba(236,201,75,.3)}
.code-block code .code-line{display:block;padding:0 1px}
.code-block code .code-line::before{counter-increment:line;content:counter(line);display:inline-block;width:2.5ch;margin-right:8px;text-align:right;color:#4a5568;font-size:11px;user-select:none}
code.inline{background:var(--surface);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:13px;color:#f59e0b}

.diff-block{margin:12px 0;border-radius:var(--radius);overflow:hidden;border:1px solid var(--border)}
.diff-header{display:flex;align-items:center;justify-content:space-between;padding:6px 12px;background:var(--code-header);font-size:12px;font-family:var(--mono)}
.diff-header span{color:var(--accent2);font-weight:500}
.diff-block pre{background:#0d1117;padding:8px 0 8px 0;overflow-x:auto;margin:0;display:flex}
.diff-block code{font-family:var(--mono);font-size:13px;line-height:1.5;color:#e2e8f0;counter-reset:dline;display:block;flex:1;min-width:0}
.diff-block code .diff-line{display:block;padding:0 1px}
.diff-block code .diff-line::before{counter-increment:dline;content:counter(dline);display:inline-block;width:2.5ch;margin-right:8px;text-align:right;color:#4a5568;font-size:11px;user-select:none}
.diff-block code .diff-line.diff-removed{background:rgba(229,62,62,.15);color:#fc8181}
.diff-block code .diff-line.diff-removed::before{counter-increment:dline;content:counter(dline) " −";color:#e53e3e;font-weight:700}
.diff-block code .diff-line.diff-added{background:rgba(72,187,120,.15);color:#9ae6b4}
.diff-block code .diff-line.diff-added::before{counter-increment:dline;content:counter(dline) " +";color:#48bb78;font-weight:700}

#footer{flex-shrink:0;padding:12px 20px 20px;background:var(--bg)}
#input-wrap{max-width:780px;margin:0 auto;display:flex;gap:10px;align-items:flex-end}
#input-area{flex:1;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;align-items:flex-end;padding:4px 4px 4px 14px;transition:border-color .2s}
#input-area:focus-within{border-color:var(--accent)}
#input{flex:1;background:none;border:none;color:var(--text);font-size:14px;font-family:var(--font);padding:10px 0;outline:none;resize:none;max-height:150px;line-height:1.5}
#input::placeholder{color:var(--text3)}
#send-btn{width:36px;height:36px;border-radius:10px;border:none;background:var(--accent);color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;flex-shrink:0}
#send-btn:hover{background:var(--accent2)}
#send-btn:disabled{opacity:.4;cursor:default}
#send-btn svg{width:18px;height:18px}

.msg .msg-time{font-size:11px;color:var(--text3);padding-left:38px;margin-top:4px}
.msg-you .msg-time{padding-left:0;text-align:right}

.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text3);gap:12px}
.empty-state .logo{font-size:48px;color:var(--accent)}
.empty-state h2{font-size:20px;color:var(--text);font-weight:500}
.empty-state p{font-size:14px}

/* Split panel layout */
#content-area{display:flex;flex:1;overflow:hidden}
#chat-panel{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}
#resize-handle{width:4px;background:var(--border);cursor:col-resize;flex-shrink:0;transition:background .15s}
#resize-handle:hover{background:var(--accent)}
#resize-handle.active{background:var(--accent)}
#right-panel{width:450px;display:flex;flex-direction:column;border-left:1px solid var(--border);flex-shrink:0;overflow:hidden;background:var(--bg)}
#right-panel.hidden{display:none}
#files-section{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
#files-toolbar{display:flex;align-items:center;padding:6px 10px;border-bottom:1px solid var(--border);gap:6px;flex-shrink:0}
#files-toolbar button{background:var(--surface);border:1px solid var(--border);color:var(--text2);padding:3px 8px;border-radius:6px;cursor:pointer;font-size:12px;font-family:var(--font)}
#files-toolbar button:hover{background:var(--surface2);color:var(--text)}
#files-toolbar span{font-size:12px;color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#file-tree{flex:1;overflow-y:auto;padding:4px 0;font-family:var(--mono);font-size:13px}
.file-item{padding:4px 12px 4px 0;cursor:pointer;display:flex;align-items:center;gap:6px;color:var(--text2);white-space:nowrap}
.file-item:hover{background:var(--surface)}
.file-item.selected{background:var(--surface2);color:var(--text)}
.file-item .file-icon{width:16px;text-align:center;flex-shrink:0;font-size:12px}
.file-item .file-name{overflow:hidden;text-overflow:ellipsis}
.file-item .file-size{margin-left:auto;color:var(--text3);font-size:11px;padding-right:12px;flex-shrink:0}
.file-dir{padding-left:0}
#file-viewer{flex:1;overflow:auto;display:none;background:#0d1117}
#file-viewer pre{margin:0;padding:12px;font-family:var(--mono);font-size:13px;color:#e2e8f0;white-space:pre-wrap;word-wrap:break-word}
#file-viewer-header{padding:6px 10px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text3);font-family:var(--mono);display:flex;align-items:center;justify-content:space-between}
#file-viewer-header .close-btn{background:none;border:none;color:var(--text3);cursor:pointer;font-size:16px}
/* Horizontal resize handle between files and terminal */
#h-resize-handle{height:4px;background:var(--border);cursor:row-resize;flex-shrink:0;transition:background .15s}
#h-resize-handle:hover{background:var(--accent)}
#h-resize-handle.active{background:var(--accent)}
/* Terminal section */
#terminal-section{height:250px;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;background:#0d1117}
#terminal-section.minimized{height:0}
#terminal-container{flex:1;overflow:hidden;padding:2px}

/* Topbar toggle button */
#panel-toggle{background:none;border:1px solid var(--border);color:var(--text3);padding:4px 8px;border-radius:6px;cursor:pointer;font-size:11px;font-family:var(--font);margin-right:8px;transition:all .15s}
#panel-toggle:hover{color:var(--accent);border-color:var(--accent)}
#panel-toggle.active{color:var(--accent);border-color:var(--accent)}

/* Execute button on code blocks */
.code-block-exec{background:none;border:1px solid var(--border);color:#48bb78;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-family:var(--font);margin-right:6px;transition:all .15s}
.code-block-exec:hover{background:rgba(72,187,120,.15);border-color:#48bb78}
.code-block-exec.running{color:#ecc94b;border-color:#ecc94b}

/* Exec result badge */
.exec-result{margin:12px 0;padding:10px 14px;border-radius:8px;font-family:var(--mono);font-size:12px;border:2px solid var(--border);animation:fadeIn .3s}
.exec-result.success{border-color:#48bb78;background:rgba(72,187,120,.08);color:#48bb78}
.exec-result.error{border-color:#e53e3e;background:rgba(229,62,62,.08);color:#e53e3e}
.exec-result .exec-code{font-size:11px;font-weight:600;margin-bottom:4px}
.exec-result.success .exec-code{color:#48bb78}
.exec-result.error .exec-code{color:#e53e3e}
.exec-result .exec-output{color:var(--text);white-space:pre-wrap;margin-top:4px;font-size:12px}
.exec-result .exec-warnings{color:#ecc94b;white-space:pre-wrap;margin-top:4px;padding:6px 8px;background:rgba(236,201,75,.08);border-radius:4px;border:1px solid rgba(236,201,75,.2);font-size:12px}

/* Pipeline progress */
.pipeline-progress{margin:12px 0;padding:12px 14px;border-radius:8px;border:1px solid var(--border);background:var(--surface);animation:fadeIn .3s}
.pipeline-header{font-size:13px;font-weight:600;color:var(--text);margin-bottom:8px}
.pipeline-nodes{display:flex;flex-wrap:wrap;gap:6px}
.pipeline-node{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:16px;font-size:12px;font-weight:500;border:1px solid var(--border);background:var(--surface2);transition:all .3s}
.pipeline-node.pending{color:var(--muted)}
.pipeline-node.running{color:var(--accent);border-color:var(--accent);background:rgba(139,92,246,.08);animation:pulse 1.5s infinite}
.pipeline-node.success{color:#48bb78;border-color:#48bb78;background:rgba(72,187,120,.08)}
.pipeline-node.failed{color:#e53e3e;border-color:#e53e3e;background:rgba(229,62,62,.08)}
.pipeline-node.skipped{color:var(--muted);border-color:var(--border);opacity:.5}
.pn-icon{font-size:14px}
.pn-name{font-size:11px}
.pn-time{font-size:10px;opacity:.6}

/* Exploit Intelligence */
.exploit-rank-header{margin-bottom:16px}
.exploit-rank-header h2{font-size:18px;margin:0 0 4px 0;color:var(--text)}
.rank-count{font-size:13px;background:var(--accent);color:#fff;padding:2px 8px;border-radius:10px;vertical-align:middle;margin-left:6px}
.rank-target{font-size:13px;color:var(--text3)}

.exploit-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin:10px 0;overflow:hidden;transition:border-color .2s}
.exploit-card:hover{border-color:var(--accent)}
.exploit-card-head{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--surface2);border-bottom:1px solid var(--border)}
.exploit-rank{font-size:14px;font-weight:700;color:var(--accent);min-width:28px}
.exploit-cve{font-size:15px;font-weight:600;color:var(--text);font-family:var(--mono)}
.exploit-score{margin-left:auto;font-size:20px;font-weight:800;font-family:var(--mono)}
.exploit-score.high{color:#48bb78}
.exploit-score.medium{color:#ecc94b}
.exploit-score.low{color:#e53e3e}
.exploit-card-body{padding:14px 16px}
.exploit-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.exploit-type,.exploit-severity,.exploit-target{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:500}
.exploit-type{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.2)}
.exploit-severity{background:rgba(229,62,62,.1);color:#e53e3e;border:1px solid rgba(229,62,62,.2)}
.exploit-severity.sev-low{background:rgba(72,187,120,.1);color:#48bb78;border-color:rgba(72,187,120,.2)}
.exploit-severity.sev-medium{background:rgba(236,201,75,.1);color:#ecc94b;border-color:rgba(236,201,75,.2)}
.exploit-target{background:rgba(66,153,225,.1);color:#63b3ed;border:1px solid rgba(66,153,225,.2)}
.exploit-msf{display:flex;align-items:center;gap:8px;margin:8px 0;padding:6px 10px;background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.15);border-radius:6px}
.msf-label{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#a78bfa;font-weight:600}
.exploit-msf code{font-size:12px;color:var(--text);word-break:break-all}
.exploit-desc{font-size:13px;color:var(--text3);line-height:1.5;margin:8px 0}
.exploit-scores{margin-top:10px}
.score-bar-row{display:flex;align-items:center;gap:8px;margin:4px 0}
.score-label{font-size:11px;color:var(--text3);min-width:110px;text-align:right}
.score-bar-bg{flex:1;height:6px;background:var(--surface2);border-radius:3px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:3px;transition:width .5s ease}
.score-bar-fill.high{background:linear-gradient(90deg,#48bb78,#38a169)}
.score-bar-fill.medium{background:linear-gradient(90deg,#ecc94b,#d69e2e)}
.score-bar-fill.low{background:linear-gradient(90deg,#e53e3e,#c53030)}
.score-val{font-size:11px;font-weight:600;color:var(--text);min-width:24px}

.poc-section{margin-top:16px}
.poc-section h2{font-size:16px;margin:0 0 12px 0;color:var(--text)}
.poc-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin:10px 0;overflow:hidden}
.poc-header{display:flex;align-items:center;gap:10px;padding:10px 16px;background:var(--surface2);border-bottom:1px solid var(--border)}
.poc-card pre{margin:0;border-radius:0;border:none}
.poc-card code{font-size:12px}

.exploit-poc{margin:12px -16px -14px;padding:0;background:var(--code-bg);border-top:1px solid var(--border)}
.exploit-poc .poc-header{padding:8px 16px;background:var(--code-header);border-bottom:1px solid var(--border)}
.poc-label{font-size:11px;font-weight:600;color:var(--accent2);text-transform:uppercase;letter-spacing:.5px}
.exploit-poc pre{margin:0;border-radius:0;border:none;padding:12px 16px;overflow-x:auto}
.exploit-poc code{font-size:12px}

.guide-header{margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.guide-header h1{margin:0 0 8px 0;font-size:20px;color:var(--text)}
.guide-target,.guide-goal{font-size:13px;color:var(--text3);margin:2px 0}
.guide-target strong{color:var(--text)}
.guide-section{margin:0}
.guide-section h2{font-size:16px;color:var(--text);margin:0 0 10px 0;padding-bottom:6px;border-bottom:1px solid var(--border)}
.vuln-detail{display:flex;align-items:center;gap:8px;padding:1px 0;font-size:13px}
.vuln-label{color:var(--text3);min-width:100px}
.vuln-detail code{background:var(--surface2);padding:2px 6px;border-radius:4px;font-size:12px}

.mit-row{display:flex;align-items:center;gap:8px;padding:6px 0}
.mit-icon{font-size:14px}
.mit-name{font-size:12px;font-weight:600;color:var(--text);min-width:100px}
.mit-status{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:500}
.mit-status.mit-on{background:rgba(229,62,62,.1);color:#e53e3e}
.mit-status.mit-off{background:rgba(72,187,120,.1);color:#48bb78}
.mit-note{font-size:12px;color:var(--text3);padding:2px 0 4px 28px;line-height:1.4}
.mit-summary{margin-top:10px;padding:8px 12px;background:var(--surface2);border-radius:6px;font-size:13px}
.mit-verdict{margin-top:8px;padding:8px 12px;border-radius:6px;font-size:13px;font-weight:500}
.mit-verdict.hard{background:rgba(229,62,62,.08);color:#e53e3e;border:1px solid rgba(229,62,62,.15)}
.mit-verdict.moderate{background:rgba(236,201,75,.08);color:#ecc94b;border:1px solid rgba(236,201,75,.15)}
.mit-verdict.easy{background:rgba(72,187,120,.08);color:#48bb78;border:1px solid rgba(72,187,120,.15)}

.step-card{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}
.step-card:last-child{border-bottom:none}
.step-num{min-width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;border-radius:50%;font-size:14px;font-weight:700;flex-shrink:0}
.step-content{flex:1}
.step-content h3{margin:0 0 6px 0;font-size:14px;color:var(--text)}
.step-content p{margin:4px 0;font-size:13px;color:var(--text3);line-height:1.5}
.step-content ul,.step-content ol{margin:4px 0;padding-left:20px;font-size:13px;color:var(--text3)}
.step-content li{margin:2px 0}
.step-content pre{margin:6px 0;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;overflow-x:auto}
.step-content code{font-size:12px}

.cve-explain{padding:2px 0}
.cve-explain-header{margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.cve-explain-header h1{margin:0 0 4px 0;font-size:22px;color:var(--text);font-family:var(--mono)}
.cve-explain p{font-size:14px;color:var(--text2);line-height:1.4;margin:2px 0}
.cve-explain ul{padding-left:20px;margin:2px 0}
.cve-explain li{font-size:13px;color:var(--text2);margin:1px 0}
.cve-details{display:flex;flex-direction:column;gap:2px}

/* Pentest tool output — compact text-first */
.pentest-text{font-size:13px;color:var(--text2);line-height:1.7}
.pentest-text b{color:var(--text);font-weight:600}
.pentest-text-dim{color:var(--text3);font-size:12px}
.pentest-inline-badge{font-size:10px;font-weight:700;letter-spacing:.3px;padding:1px 5px;border-radius:3px;text-transform:uppercase;vertical-align:middle;margin-right:2px}
.pentest-inline-badge.nmap{background:rgba(66,153,225,.12);color:#4299e1}
.pentest-inline-badge.hydra{background:rgba(229,62,62,.1);color:#e53e3e}
.pentest-inline-badge.sqlmap{background:rgba(236,201,75,.1);color:#ecc94b}
.pentest-inline-badge.nikto{background:rgba(159,122,234,.1);color:#9f7aea}
.pentest-inline-badge.john{background:rgba(72,187,120,.1);color:#48bb78}
.pentest-inline-badge.msfconsole{background:rgba(66,153,225,.08);color:#63b3ed}
.pentest-inline-badge.netcat{background:var(--surface2);color:var(--text3)}
.pentest-inline-badge.generic{background:var(--surface2);color:var(--text3)}

/* Pentest tool execution results — card layout for scan output */
.pentest-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin:8px 0;overflow:hidden;font-size:13px}
.pentest-card-header{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface2);border-bottom:1px solid var(--border)}
.pentest-tool-badge{font-size:10px;font-weight:700;letter-spacing:.3px;padding:2px 6px;border-radius:3px;text-transform:uppercase}
.pentest-tool-badge.nmap{background:rgba(66,153,225,.15);color:#4299e1}
.pentest-tool-badge.hydra{background:rgba(229,62,62,.12);color:#e53e3e}
.pentest-tool-badge.sqlmap{background:rgba(236,201,75,.12);color:#ecc94b}
.pentest-tool-badge.nikto{background:rgba(159,122,234,.12);color:#9f7aea}
.pentest-tool-badge.john{background:rgba(72,187,120,.12);color:#48bb78}
.pentest-tool-badge.generic{background:var(--surface);color:var(--text3);border:1px solid var(--border)}
.pentest-cmd{font-size:11px;font-family:var(--mono);color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.pentest-exit{font-size:11px;color:var(--text3);font-family:var(--mono);flex-shrink:0}
.pentest-host{padding:10px 12px}
.pentest-host+.pentest-host{border-top:1px solid var(--border)}
.pentest-host-header{display:flex;align-items:center;gap:6px;margin-bottom:6px}
.pentest-host-icon{color:#48bb78;font-size:11px}
.pentest-host-addr{font-size:12px;font-weight:600;color:var(--text);font-family:var(--mono)}
.pentest-os{font-size:11px;color:var(--text3);background:var(--surface2);padding:2px 6px;border-radius:3px}
.pentest-profile{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;margin-bottom:4px}
.pentest-profile-item{font-size:11px;color:var(--text3);display:flex;align-items:center;gap:4px}
.pentest-profile-label{color:var(--text3);font-weight:500}
.pentest-profile-val{color:var(--text2);font-family:var(--mono)}
.pentest-table{width:100%;border-collapse:collapse;font-size:12px}
.pentest-table th{text-align:left;padding:5px 8px;background:var(--surface2);color:var(--text3);font-weight:500;font-size:10px;text-transform:uppercase;letter-spacing:.3px;border-bottom:1px solid var(--border)}
.pentest-table td{padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.03);color:var(--text2)}
.pentest-port{font-family:var(--mono);font-weight:600;color:var(--text)!important}
.pentest-state{font-size:11px}
.state-open{color:#48bb78}
.pentest-svc{font-weight:500}
.svc-high{color:#e53e3e}
.svc-med{color:#ecc94b}
.pentest-ver{font-size:11px;color:var(--text3);font-family:var(--mono)}
.pentest-cred{font-family:var(--mono);font-weight:500;color:#ecc94b!important}
.pentest-summary{padding:8px 12px;font-size:12px;color:var(--text3)}
.pentest-findings{padding:8px 12px 0;font-size:12px;font-weight:600;color:var(--accent)}
.pentest-vuln{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.03)}
.pentest-vuln:last-child{border-bottom:none}
.pentest-vuln-title{font-size:12px;font-weight:600;color:var(--text);margin-bottom:3px}
.pentest-vuln-detail{font-size:11px;color:var(--text3);margin:1px 0}
.pentest-scripts{padding:6px 12px;background:var(--surface2);border-top:1px solid var(--border)}
.pentest-scripts-title{font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:3px}
.pentest-script-line{font-size:11px;color:var(--text2);font-family:var(--mono);padding:1px 0}
.pentest-finding{padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;color:var(--text2);line-height:1.4}
.pentest-finding:last-child{border-bottom:none}
.pentest-finding-list{padding:0}
.pentest-host-info{display:flex;gap:12px;padding:6px 12px;background:var(--surface2);border-bottom:1px solid var(--border);font-size:11px;color:var(--text3)}
.pentest-db-list{padding:8px 12px;border-top:1px solid var(--border)}
.pentest-db-title{font-size:11px;font-weight:600;color:var(--text3);margin-bottom:4px}
.pentest-db-chip{display:inline-block;padding:2px 6px;margin:2px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;font-size:11px;font-family:var(--mono);color:var(--text2)}
.pentest-status{font-size:10px;color:var(--text3);padding:2px 12px;font-family:var(--mono)}
.pentest-output{margin:0;padding:10px 12px;font-size:11px;color:var(--text2);overflow-x:auto;background:var(--code-bg)}
.pentest-output code{font-size:11px}

/* Exploit discovery card */
.pentest-exploit-card{border-color:rgba(229,62,62,.2)}
.pentest-tool-badge.exploit{background:rgba(229,62,62,.12);color:#e53e3e}
.pentest-exploit-svc{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface2);border-bottom:1px solid var(--border)}
.pentest-exploit-port{font-family:var(--mono);font-weight:700;font-size:13px;color:var(--text)}
.pentest-exploit-svcname{font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.3px}
.pentest-exploit-action{font-size:10px;font-weight:600;color:var(--accent);cursor:pointer;padding:1px 5px;border:1px solid var(--accent);border-radius:3px;opacity:.7}
.pentest-exploit-action:hover{opacity:1;background:rgba(139,92,246,.1)}
.pentest-exploit-hint{padding:8px 12px;font-size:11px;color:var(--text3);border-top:1px solid var(--border);background:var(--surface2)}

/* Terminal */
#terminal-container .xterm{padding:4px}

@media(max-width:768px){
  #sidebar{position:fixed;top:0;left:0;height:100%;z-index:100}
  #sidebar.collapsed{margin-left:-260px}
  #right-panel{display:none!important}
}
</style>
</head>
<body>

<div id="sidebar">
  <div id="sidebar-header">
    <button id="new-chat-btn" onclick="newChat()">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      New Chat
    </button>
    <button id="settings-btn" onclick="openSettings()" title="Settings">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    </button>
  </div>
  <div id="chat-list"></div>
  <div id="sidebar-footer">
    <button class="sidebar-btn" onclick="toggleTTS()">
      <span id="tts-dot"></span>
      <span id="tts-label">Speak: ON</span>
    </button>
    <button class="sidebar-btn" onclick="toggleMic()">
      <span id="mic-dot"></span>
      <span id="mic-label">Mic: ON</span>
      <span id="mic-level-wrap"><span id="mic-level"><span id="mic-level-bar"></span><span id="mic-threshold"></span></span></span>
    </button>
    <button class="sidebar-btn danger" onclick="if(confirm('Clear conversation history?'))fetch('/newchat').then(()=>loadChats())">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
      Clear History
    </button>
  </div>
</div>

<div id="main">
  <div id="topbar">
    <div id="menu-btn" onclick="toggleSidebar()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </div>
    <div id="top-title">Jarvis</div>
    <button id="panel-toggle" onclick="togglePanel()">&#9776; Dev</button>
    <div id="status-pill" class="idle" onclick="toggleSysPopup()">Idle</div>
  </div>
  <div id="sys-popup">
    <h3>System</h3>
    <div id="sys-mem-section"></div>
    <div id="sys-task-section"></div>
    <div id="sys-procs"></div>
  </div>
  <div id="content-area">
    <div id="chat-panel">
      <div id="chat-area"><div id="chat-inner"></div></div>
      <div id="footer">
        <div id="input-wrap">
          <div id="input-area">
            <textarea id="input" rows="1" placeholder="Message Jarvis..." autofocus></textarea>
            <button id="send-btn" onclick="sendMsg()">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            </button>
          </div>
        </div>
      </div>
    </div>
    <div id="resize-handle"></div>
    <div id="right-panel" class="hidden">
      <div id="files-section">
        <div id="files-toolbar">
          <button onclick="refreshFiles()">&#8635;</button>
          <span id="files-path">/workspace</span>
        </div>
        <div id="file-tree"></div>
        <div id="file-viewer">
          <div id="file-viewer-header"><span id="file-viewer-name"></span><button class="close-btn" onclick="closeFileViewer()">&times;</button></div>
          <pre id="file-viewer-content"></pre>
        </div>
      </div>
      <div id="h-resize-handle"></div>
      <div id="terminal-section">
        <div id="terminal-container"></div>
      </div>
    </div>
  </div>
</div>

<script>
let lastCount=0,activeChatId=null,micMuted=false,ttsMuted=false,sentTexts=new Set(),lastDataJSON='';
const chatInner=document.getElementById('chat-inner');
const input=document.getElementById('input');
const chatArea=document.getElementById('chat-area');
const statusPill=document.getElementById('status-pill');
let jMsg=null,jBody=null,jThink='',jOpen=false;

input.addEventListener('input',function(){
  this.style.height='auto';
  this.style.height=Math.min(this.scrollHeight,150)+'px';
});
input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg()}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){fetch('/stop').catch(()=>{});}});

function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('collapsed');
}

function escapeHtml(t){
  return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderMarkdown(text){
  let filePath='';
  let fm=text.match(/\\*\\*File:\\*\\*\\s*`([^`]+)`/);
  if(fm) filePath=fm[1];
  text=text.replace(/\\n?\\*\\*File:\\*\\*\\s*`[^`]*`\\n?/g,'\\n');
  let runCmds={c:'gcc -Wall -Wextra -Werror -o pipeline_run {f} && ./pipeline_run',cpp:'g++ -Wall -Wextra -Werror -o pipeline_run {f} && ./pipeline_run',python:'python3 {f}',python3:'python3 {f}',java:'javac {f} && java pipeline_run',rust:'rustc -W warnings -o pipeline_run {f} && ./pipeline_run',go:'go build -o pipeline_run {f} && ./pipeline_run',javascript:'node {f}',js:'node {f}',bash:'bash {f}',sh:'sh {f}'};
  let blocks=[];
  function findCodeBlocks(src){
    let out='';let i=0;let isOutputBlock=false;let isTestBlock=false;let lastCodeEnd=0;
    while(i<src.length){
      if(src[i]==='`'&&src[i+1]==='`'&&src[i+2]==='`'){
        let between=src.substring(lastCodeEnd,i);
        if(/\\*\\*Output:\\*\\*/.test(between)){isOutputBlock=true;isTestBlock=false;}
        else if(/\\*\\*Test Result:\\*\\*/.test(between)){isTestBlock=true;isOutputBlock=false;}
        out=out.replace(/\\*\\*Output:\\*\\*/g,'').replace(/\\*\\*Test Result:\\*\\*/g,'');
        let start=i+3;
        let langEnd=src.indexOf('\\n',start);
        if(langEnd===-1){out+=src.substring(i);break;}
        let lang=src.substring(start,langEnd).trim();
        i=langEnd+1;
        let endIdx=-1;let searchFrom=i;
        while(true){
          let pos=src.indexOf('```',searchFrom);
          if(pos===-1)break;
          if(pos>0&&src[pos-1]==='\\n'&&src[pos+3]==='\\n'){
            endIdx=pos;break;}
          else if(pos>0&&src[pos-1]==='\\n'&&pos+3>=src.length){
            endIdx=pos;break;}
          else if(pos===0||src[pos-1]==='\\n'){
            let numBackticks=3;
            while(src[pos+numBackticks]==='`')numBackticks++;
            if(pos+numBackticks>=src.length||src[pos+numBackticks]==='\\n'){
              endIdx=pos;break;}
          }
          searchFrom=pos+3;
        }
        if(endIdx===-1){
          // Unclosed code block — treat rest of text as code
          let code=src.substring(i);
          i=src.length;
          let id=blocks.length;
          let langAttr=lang?' class="language-'+escapeHtml(lang)+'"':'';
          let raw=code.split('\\n').map(function(l){return l.replace(/^[+−]\\s?/,'');}).join('\\n');
          let highlighted;
          try{
            if(lang&&hljs.getLanguage(lang)){highlighted=hljs.highlight(raw,{language:lang}).value;}
            else{highlighted=hljs.highlightAuto(raw).value;}
          }catch(e){highlighted=escapeHtml(raw);}
          let hlines=highlighted.split('\\n').map(function(l){return '<span class="code-line">'+l+'</span>';}).join('\\n');
          let metaHtml='';
          if(filePath&&!isOutputBlock){
            let fileName=filePath.split('/').pop()||filePath;
            metaHtml='<span class="code-block-file">'+escapeHtml(fileName)+'</span>';
          }
          blocks.push('<div class="code-block"><div class="code-block-header">'+metaHtml+'<span class="code-block-lang">'+escapeHtml(lang||'code')+'</span><button class="code-block-copy" onclick="copyCode(this,'+id+')">Copy</button></div><pre><code'+langAttr+'>'+hlines+'</code></pre></div>');
          break;
        }
        let code=src.substring(i,endIdx);
        i=endIdx+3;
        if(i<src.length&&src[i]==='\\n')i++;
        let id=blocks.length;
        if(lang==='diff'){
          let dlines=code.split('\\n');
          let diffLines=[];
          for(let l of dlines){
            let raw=l;
            if(raw.startsWith('- ')){diffLines.push({type:'remove',text:raw.substring(2)});}
            else if(raw.startsWith('+ ')){diffLines.push({type:'add',text:raw.substring(2)});}
            else if(raw.trim()){diffLines.push({type:'neutral',text:raw});}
          }
          let diffHtml='';
          if(diffLines.length){
            diffHtml+='<pre><code>';
            for(let d of diffLines){
              if(d.type==='remove') diffHtml+='<span class="diff-line diff-removed">'+escapeHtml(d.text)+'</span>';
              else if(d.type==='add') diffHtml+='<span class="diff-line diff-added">'+escapeHtml(d.text)+'</span>';
              else diffHtml+='<span class="diff-line">'+escapeHtml(d.text)+'</span>';
            }
            diffHtml+='</code></pre>';
          }
          blocks.push('<div class="diff-block"><div class="diff-header"><span>Changes</span></div>'+diffHtml+'</div>');
          isOutputBlock=false;isTestBlock=false;
        } else {
          let langAttr=lang?' class="language-'+escapeHtml(lang)+'"':'';
          let raw=code.split('\\n').map(function(l){return l.replace(/^[+−]\\s?/,'');}).join('\\n');
          let highlighted;
          try{
            if(lang&&hljs.getLanguage(lang)){highlighted=hljs.highlight(raw,{language:lang}).value;}
            else{highlighted=hljs.highlightAuto(raw).value;}
          }catch(e){highlighted=escapeHtml(raw);}
          let hlines=highlighted.split('\\n').map(function(l){return '<span class="code-line">'+l+'</span>';}).join('\\n');
          let metaHtml='';
          if(filePath&&!isOutputBlock){
            let fileName=filePath.split('/').pop()||filePath;
            metaHtml='<span class="code-block-file">'+escapeHtml(fileName)+'</span>';
          }
          let outputCls=isOutputBlock?' code-block-output':'';
          let testCls=isTestBlock?' code-block-test':'';
          if(isOutputBlock){metaHtml='<span class="code-block-lang" style="color:#48bb78">Output</span>';}
          if(isTestBlock){metaHtml='<span class="code-block-lang" style="color:#ecc94b">Test Result</span>';}
          let hideCopy=isOutputBlock||isTestBlock;
          blocks.push('<div class="code-block'+outputCls+testCls+'"><div class="code-block-header">'+metaHtml+(hideCopy?'':'<span class="code-block-lang">'+escapeHtml(lang||'code')+'</span>')+(hideCopy?'':'<button class="code-block-copy" onclick="copyCode(this,'+id+')">Copy</button>')+'</div><pre><code'+langAttr+'>'+hlines+'</code></pre></div>');
          if(isOutputBlock) isOutputBlock=false;
          if(isTestBlock) isTestBlock=false;
        }
        out+='%%CB_'+id+'_CB%%';
        lastCodeEnd=i;
      } else {
        out+=src[i];i++;
      }
    }
    return out.replace(/\\*\\*Output:\\*\\*/g,'').replace(/\\*\\*Test Result:\\*\\*/g,'');
  }
  let html=findCodeBlocks(text);
  let imgs=[];let ii=0;
  html=html.replace(/<(img|video)[^>]*>(?:<\\/\\1>)?/g,function(m){imgs.push(m);return '%%IMG_'+ii+'_IMG%%';ii++;});
  let exploitBlocks=[];let eb=0;
  html=html.replace(/<!--EXPLOIT_START-->([\\s\\S]*?)<!--EXPLOIT_END-->/g,function(m,body){exploitBlocks.push(body);return '%%EB_'+eb+'_EB%%';eb++;});
  html=html.replace(/<!--PENTEST_START-->([\\s\\S]*?)<!--PENTEST_END-->/g,function(m,body){exploitBlocks.push(body);return '%%EB_'+eb+'_EB%%';eb++;});
  html=escapeHtml(html);
  html=html.replace(/%%IMG_(\\d+)_IMG%%/g,function(_,i){return imgs[i];});
  html=html.replace(/%%EB_(\\d+)_EB%%/g,function(_,i){return exploitBlocks[i];});
  html=html.replace(/`([^`]+)`/g,'<code class="inline">$1</code>');
  html=html.replace(/\*\*\*(.+?)\*\*\*/g,'<strong><em>$1</em></strong>');
  html=html.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
  html=html.replace(/\*(.+?)\*/g,'<em>$1</em>');
  html=html.replace(/\\n\\n/g,'</p><p>');
  html=html.replace(/\\n/g,'<br>');
  html=html.replace(/%%CB_(\\d+)_CB%%/g,function(_,i){return blocks[i]});
  let wrapper = /<(img|video)[^>]*>/.test(html) ? 'div' : 'p';
  return '<'+wrapper+'>'+html+'</'+wrapper+'>';
}

function copyCode(btn,id){
  let msg=btn.closest('.msg-jarvis')||btn.closest('.msg')||document;
  let code=msg.querySelectorAll('.code-block')[id];
  if(!code){code=document.querySelectorAll('.code-block')[id];}
  navigator.clipboard.writeText(code.querySelector('code').textContent).then(()=>{
    btn.textContent='Copied!';
    btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied')},2000);
  });
}

function clearThinking(){
  if(jMsg&&jMsg.parentNode){jMsg.parentNode.removeChild(jMsg);}
  jMsg=null;jBody=null;jThink='';jOpen=false;
}

function mkJarvis(){
  clearThinking();
  let d=document.createElement('div');
  d.className='msg msg-jarvis';
  d.innerHTML='<div class="msg-avatar-row"><div class="msg-avatar">J</div><div class="msg-sender">Jarvis</div></div><div class="thoughts"><div class="thought-header"><span class="dots"><span></span><span></span><span></span></span><span>Thinking...</span><span class="arrow">&#9660;</span></div><div class="thought-body"></div></div><div class="msg-body"></div>';
  let h=d.querySelector('.thought-header');
  let b=d.querySelector('.thought-body');
  h.onclick=()=>{
    if(!jThink&&!d.querySelector('.msg-body').textContent)return;
    jOpen=!jOpen;
    b.classList.toggle('open',jOpen);
    h.querySelector('span:nth-child(3)').innerHTML=jOpen?'&#9650;':'&#9660;';
  };
  chatInner.appendChild(d);
  chatArea.scrollTop=chatArea.scrollHeight;
  jMsg=d;jBody=b;jThink='';jOpen=false;
}

function doneJarvis(){
  if(!jMsg)return;
  let h=jMsg.querySelector('.thought-header');
  let dots=h.querySelector('.dots');
  if(dots)dots.remove();
  h.querySelector('span:nth-child(2)').textContent='Thought';
}

function renderMsg(m,idx){
  let ti=m.msgIdx;
  if(m.sender==='Jarvis'){
    if(jMsg){
      jMsg.querySelector('.msg-body').innerHTML=renderMarkdown(m.text);
      if(m.ts){let t=document.createElement('div');t.className='msg-time';t.textContent=m.ts;jMsg.appendChild(t);}
      let nav='';
      if(m.branchCount>1)nav='<div class="branch-nav"><button onclick="switchBranch('+ti+','+(m.branchIdx-1)+')" '+(m.branchIdx===0?'disabled':'')+'>&#9664;</button><span>'+(m.branchIdx+1)+'/'+m.branchCount+'</span><button onclick="switchBranch('+ti+','+(m.branchIdx+1)+')" '+(m.branchIdx>=m.branchCount-1?'disabled':'')+'>&#9654;</button><button class="branch-del" onclick="deleteBranch('+ti+','+m.branchIdx+')" title="Delete this branch">&times;</button></div>';
      let eb=document.createElement('div');
      eb.className='msg-edit';
      eb.innerHTML=nav+'<button onclick="editFrom('+ti+')" title="Edit from here">&#8634;</button>';
      jMsg.appendChild(eb);
      doneJarvis();
      jMsg=null;jBody=null;jThink='';jOpen=false;
      return null;
    }
    let d=document.createElement('div');
    d.className='msg msg-jarvis';
    let nav='';
    if(m.branchCount>1)nav='<div class="branch-nav"><button onclick="switchBranch('+ti+','+(m.branchIdx-1)+')" '+(m.branchIdx===0?'disabled':'')+'>&#9664;</button><span>'+(m.branchIdx+1)+'/'+m.branchCount+'</span><button onclick="switchBranch('+ti+','+(m.branchIdx+1)+')" '+(m.branchIdx>=m.branchCount-1?'disabled':'')+'>&#9654;</button><button class="branch-del" onclick="deleteBranch('+ti+','+m.branchIdx+')" title="Delete this branch">&times;</button></div>';
    let h='<div class="msg-avatar-row"><div class="msg-avatar">J</div><div class="msg-sender">Jarvis</div></div><div class="msg-body">'+renderMarkdown(m.text)+'</div>';
    if(m.ts)h+='<div class="msg-time">'+m.ts+'</div>';
    h+='<div class="msg-edit">'+nav+'<button onclick="editFrom('+ti+')" title="Edit from here">&#8634;</button></div>';
    d.innerHTML=h;
    return d;
  }else{
    let d=document.createElement('div');
    d.className='msg msg-you';
    d.setAttribute('data-idx',ti);
    let h='<div class="msg-avatar-row"><div class="msg-avatar">U</div><div class="msg-sender">You</div></div><div class="msg-body">'+escapeHtml(m.text).replace(/\\n/g,'<br>')+'</div>';
    if(m.ts)h+='<div class="msg-time">'+m.ts+'</div>';
    h+='<div class="msg-edit"><button onclick="editMsg('+ti+')" title="Edit">&#9998;</button><button class="edit-del" onclick="deleteFrom('+ti+')" title="Delete from here">&times;</button></div>';
    d.innerHTML=h;
    return d;
  }
}

function isNearBottom(){
  return chatArea.scrollHeight-chatArea.scrollTop-chatArea.clientHeight<120;
}

function switchBranch(idx,branch){
  fetch('/switchbranch?idx='+idx+'&branch='+branch).then(()=>{
    loadMsgs().then(()=>{
      let el=chatInner.querySelector('.msg-you[data-idx="'+idx+'"]');
      if(el)el.scrollIntoView({behavior:'smooth',block:'center'});
    });
  });
}

function deleteBranch(idx,branch){
  fetch('/deletebranch?idx='+idx+'&branch='+branch).then(()=>loadMsgs());
}

function findYouMsg(ti){
  return chatInner.querySelector('.msg-you[data-idx="'+ti+'"]');
}

function editMsg(ti){
  let msg=findYouMsg(ti);
  if(!msg)return;
  let body=msg.querySelector('.msg-body');
  let origText=body.textContent;
  body.innerHTML='<div class="edit-inline"><textarea rows="3">'+escapeHtml(origText)+'</textarea><div class="edit-actions"><button class="edit-save" onclick="saveEdit('+ti+',this)">Save & Resend</button><button class="edit-cancel" onclick="cancelEdit(this)">Cancel</button></div></div>';
  body.querySelector('textarea').focus();
}

function editFrom(ti){
  let msg=findYouMsg(ti);
  if(!msg)return;
  let body=msg.querySelector('.msg-body');
  let origText=body.textContent;
  body.innerHTML='<div class="edit-inline"><textarea rows="3">'+escapeHtml(origText)+'</textarea><div class="edit-actions"><button class="edit-save" onclick="saveEditFrom('+ti+',this)">Edit & Continue</button><button class="edit-cancel" onclick="cancelEdit(this)">Cancel</button></div></div>';
  body.querySelector('textarea').focus();
}

function cancelEdit(btn){
  loadMsgs();
}

function saveEdit(idx,btn){
  let inline=btn.closest('.edit-inline');
  let newText=inline.querySelector('textarea').value.trim();
  if(!newText)return;
  fetch('/editmsg?idx='+idx+'&text='+encodeURIComponent(newText)).then(()=>{
    loadMsgs();
  });
}

function saveEditFrom(idx,btn){
  let inline=btn.closest('.edit-inline');
  let newText=inline.querySelector('textarea').value.trim();
  if(!newText)return;
  fetch('/editmsg?idx='+idx+'&text='+encodeURIComponent(newText)).then(()=>{
    loadMsgs();
  });
}

function deleteFrom(ti){
  let msg=findYouMsg(ti);
  if(!msg)return;
  let body=msg.querySelector('.msg-body');
  body.innerHTML='<div class="edit-inline"><div style="color:var(--text3);font-size:13px;margin-bottom:6px">Delete this message?</div><div class="edit-actions"><button class="edit-save" style="background:#e53e3e" onclick="confirmDeleteFrom('+ti+')">Delete</button><button class="edit-cancel" onclick="loadMsgs()">Cancel</button></div></div>';
}

function confirmDeleteFrom(ti){
  fetch('/editmsg?idx='+ti+'&text=').then(()=>{
    loadMsgs();
  });
}

async function pollStatus(){
  try{
    let r=await fetch('/status');
    let s=(await r.text()).trim();
    if(s==='1'){
      // Check thinking file for progress text
      try{
        let tr=await fetch('/think');
        let thinkText=(await tr.text()).trim();
        statusPill.textContent=thinkText&&thinkText!=='Processing...'?thinkText.substring(0,40)+'...':'Thinking...';
      }catch(e){
        statusPill.textContent='Thinking...';
      }
      statusPill.className='thinking';
    }else{
      statusPill.textContent='Idle';
      statusPill.className='idle';
    }
  }catch(e){}
  setTimeout(pollStatus,500);
}

let sysPopupOpen=false;
function toggleSysPopup(){
  sysPopupOpen=!sysPopupOpen;
  let p=document.getElementById('sys-popup');
  if(sysPopupOpen){p.classList.add('open');pollSysNow();}else{p.classList.remove('open');}
}
document.addEventListener('click',function(e){
  let p=document.getElementById('sys-popup');
  let s=document.getElementById('status-pill');
  if(sysPopupOpen&&!p.contains(e.target)&&!s.contains(e.target)){sysPopupOpen=false;p.classList.remove('open');}
});
document.addEventListener('click',function(e){
  let t=e.target;
  if(t.classList.contains('pentest-exploit-action')){
    let row=t.closest('tr');
    if(row){
      let cve=row.querySelector('code.inline');
      if(cve){
        let id=cve.textContent.trim();
        sendMsgDirect('try '+id);
      }
    }
  }
});

async function pollSysNow(){
  if(!sysPopupOpen)return;
  try{
    let r=await fetch('/sysinfo');
    let d=await r.json();
    let memPct=d.memTotal?Math.round((d.memUsed/d.memTotal)*100):0;
    let cls=memPct<60?'ok':memPct<85?'warn':'danger';
    let memHtml='<div class="sys-row"><span class="sys-label">Memory</span><span class="sys-val">'+d.memUsed+' / '+d.memTotal+' MB ('+memPct+'%)</span></div>';
    memHtml+='<div class="sys-bar"><div class="sys-bar-fill '+cls+'" style="width:'+memPct+'%"></div></div>';
    document.getElementById('sys-mem-section').innerHTML=memHtml;
    if(d.thinking){
      let taskHtml=d.task?'<div style="font-size:11px;color:var(--text3);margin-top:4px;word-break:break-word">'+d.task+'</div>':'';
      document.getElementById('sys-task-section').innerHTML='<div class="sys-row" style="margin-top:8px"><span class="sys-label">Task</span><span class="sys-val" style="color:var(--accent2)">Thinking...</span></div>'+taskHtml+'<button id="sys-stop" onclick="stopTask()">Stop</button>';
    }else{
      document.getElementById('sys-task-section').innerHTML='<div class="sys-row" style="margin-top:8px"><span class="sys-label">Status</span><span class="sys-val" style="color:#48bb78">Idle</span></div>';
    }
    let ph='';
    if(d.procs&&d.procs.length){
      d.procs.forEach(function(p){
        ph+='<div class="sys-proc"><span title="'+p.cmd+'">'+(p.cmd.length>35?p.cmd.substring(0,35)+'...':p.cmd)+'</span><span class="sys-proc-rss">'+p.rss+'MB</span></div>';
      });
    }
    document.getElementById('sys-procs').innerHTML=ph;
  }catch(e){}
}
function stopTask(){
  fetch('/stop').then(()=>{pollSysNow();});
}
setInterval(pollSysNow,3000);

async function pollThink(){
  try{
    let r=await fetch('/think');
    let t=await r.text();
    if(t&&t.trim()&&t!==jThink){
      jThink=t;
      if(jBody){
        jBody.innerHTML=t;
        if(!jOpen){jBody.classList.add('open');jOpen=true;}
      }
    }
  }catch(e){}
  setTimeout(pollThink,200);
}

async function pollMsgs(){
  try{
    let wasNearBottom=isNearBottom();
    let r=await fetch('/data');
    let data=await r.json();
    if(data.messages.length!==lastCount||JSON.stringify(data.messages)!==lastDataJSON){
      clearThinking();
      chatInner.innerHTML='';
      lastCount=0;
      let frag=document.createDocumentFragment();
      for(let i=0;i<data.messages.length;i++){
        let m=data.messages[i];
        let el=renderMsg(m,i);
        if(el)frag.appendChild(el);
      }
      chatInner.appendChild(frag);
      if(data.messages.length===0){
        chatInner.innerHTML='<div class="empty-state"><div class="logo">J</div><h2>How can I help you today?</h2><p>Start a conversation by typing below or use voice.</p></div>';
      }
      if(wasNearBottom)chatArea.scrollTop=chatArea.scrollHeight;
      lastCount=data.messages.length;
      lastDataJSON=JSON.stringify(data.messages);
    }
    if(!jMsg){
      let sr=await fetch('/status');
      let s=(await sr.text()).trim();
      if(s==='1')mkJarvis();
    }
  }catch(e){}
  setTimeout(pollMsgs,500);
}

async function sendMsg(){
  let text=input.value.trim();
  if(!text)return;
  input.value='';
  input.style.height='auto';
  clearThinking();
  let d=document.createElement('div');
  d.className='msg msg-you';
  d.innerHTML='<div class="msg-avatar-row"><div class="msg-avatar">U</div><div class="msg-sender">You</div></div><div class="msg-body">'+escapeHtml(text).replace(/\\n/g,'<br>')+'</div>';
  chatInner.appendChild(d);
  chatArea.scrollTop=chatArea.scrollHeight;
  sentTexts.add(text);
  try{await fetch('/send?text='+encodeURIComponent(text))}catch(e){}
}

async function sendMsgDirect(text){
  if(!text)return;
  clearThinking();
  let d=document.createElement('div');
  d.className='msg msg-you';
  d.innerHTML='<div class="msg-avatar-row"><div class="msg-avatar">U</div><div class="msg-sender">You</div></div><div class="msg-body">'+escapeHtml(text).replace(/\\n/g,'<br>')+'</div>';
  chatInner.appendChild(d);
  chatArea.scrollTop=chatArea.scrollHeight;
  sentTexts.add(text);
  try{await fetch('/send?text='+encodeURIComponent(text))}catch(e){}
}

async function loadChats(){
  try{
    let r=await fetch('/chats');
    let data=await r.json();
    activeChatId=data.active;
    let list=document.getElementById('chat-list');
    list.innerHTML='';
    data.chats.forEach(c=>{
      let div=document.createElement('div');
      div.className='chat-item'+(c.id===activeChatId?' active':'');
      div.innerHTML='<svg class="chat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg><div class="chat-info"><span class="chat-title">'+escapeHtml(c.title)+'</span><span class="chat-date">'+c.date+'</span></div><span class="chat-del" title="Delete">&times;</span>';
      div.querySelector('.chat-title').onclick=async()=>{
        await fetch('/switchchat?id='+c.id);
        await loadChats();
        await loadMsgs();
      };
      div.querySelector('.chat-del').onclick=async(e)=>{
        e.stopPropagation();
        if(!confirm('Delete this chat?'))return;
        await fetch('/deletechat?id='+c.id);
        await loadChats();
        await loadMsgs();
      };
      list.appendChild(div);
    });
  }catch(e){}
}

async function newChat(){
  await fetch('/newchat');
  await loadChats();
  await loadMsgs();
}

function resetChat(){
  lastCount=0;
  lastDataJSON='';
  clearThinking();
  chatInner.innerHTML='<div class="empty-state"><div class="logo">J</div><h2>How can I help you today?</h2><p>Start a conversation by typing below or use voice.</p></div>';
}

async function loadMsgs(){
  try{
    let wasNearBottom=isNearBottom();
    let r=await fetch('/data');
    let data=await r.json();
    clearThinking();
    chatInner.innerHTML='';
    lastCount=0;
    lastDataJSON='';
    let frag=document.createDocumentFragment();
    for(let i=0;i<data.messages.length;i++){
      let m=data.messages[i];
      let el=renderMsg(m,i);
      if(el)frag.appendChild(el);
    }
    chatInner.appendChild(frag);
    if(data.messages.length===0){
      chatInner.innerHTML='<div class="empty-state"><div class="logo">J</div><h2>How can I help you today?</h2><p>Start a conversation by typing below or use voice.</p></div>';
    }
    if(wasNearBottom)chatArea.scrollTop=chatArea.scrollHeight;
    lastCount=data.messages.length;
    lastDataJSON=JSON.stringify(data.messages);
  }catch(e){}
}

async function toggleMic(){
  micMuted=!micMuted;
  try{await fetch('/mic?muted='+(micMuted?'1':'0'))}catch(e){}
  updateMicUI();
}

function updateMicUI(){
  document.getElementById('mic-dot').className=micMuted?'off':'on';
  document.getElementById('mic-label').textContent='Mic: '+(micMuted?'Muted':'ON');
  if(micMuted) stopMicLevel(); else startMicLevel();
}

let micLevelTimer=null;
let micStream=null;
let micAnalyser=null;
let micDataArray=null;
function startMicLevel(){
  if(micAnalyser) return;
  const bar=document.getElementById('mic-level-bar');
  const thr=document.getElementById('mic-threshold');
  thr.style.bottom='30%';
  navigator.mediaDevices.getUserMedia({audio:true}).then(stream=>{
    micStream=stream;
    const ctx=new AudioContext();
    const src=ctx.createMediaStreamSource(stream);
    micAnalyser=ctx.createAnalyser();
    micAnalyser.fftSize=256;
    src.connect(micAnalyser);
    micDataArray=new Uint8Array(micAnalyser.frequencyBinCount);
    function poll(){
      if(!micAnalyser) return;
      micAnalyser.getByteTimeDomainData(micDataArray);
      let sum=0;
      for(let i=0;i<micDataArray.length;i++){
        let v=(micDataArray[i]-128)/128;
        sum+=v*v;
      }
      let rms=Math.sqrt(sum/micDataArray.length)*100;
      let pct=Math.min(100,Math.round(rms));
      bar.style.height=pct+'%';
      bar.style.background=pct>80?'#e53e3e':pct>40?'#ecc94b':'#48bb78';
      micLevelTimer=requestAnimationFrame(poll);
    }
    poll();
  }).catch(()=>{});
}
function stopMicLevel(){
  if(micLevelTimer){cancelAnimationFrame(micLevelTimer);micLevelTimer=null;}
  if(micStream){micStream.getTracks().forEach(t=>t.stop());micStream=null;}
  micAnalyser=null;
  const bar=document.getElementById('mic-level-bar');
  if(bar) bar.style.height='0%';
}

async function pollMic(){
  try{
    let r=await fetch('/micstatus');
    let s=(await r.text()).trim();
    micMuted=s==='1';
    updateMicUI();
  }catch(e){}
  setTimeout(pollMic,2000);
}

async function toggleTTS(){
  ttsMuted=!ttsMuted;
  try{await fetch('/tts?muted='+(ttsMuted?'1':'0'))}catch(e){}
  updateTTSUI();
}

function updateTTSUI(){
  document.getElementById('tts-dot').className=ttsMuted?'off':'on';
  document.getElementById('tts-label').textContent='Speak: '+(ttsMuted?'Muted':'ON');
}

async function pollTTS(){
  try{
    let r=await fetch('/ttsstatus');
    let s=(await r.text()).trim();
    ttsMuted=s==='1';
    updateTTSUI();
  }catch(e){}
  setTimeout(pollTTS,2000);
}

/* Pipeline progress display */
let lastPipelineJson='';
let pipelineEl=null;

function renderPipeline(p){
  if(!p||p.status==='idle'){
    if(pipelineEl){pipelineEl.remove();pipelineEl=null;}
    return;
  }
  if(!pipelineEl){
    pipelineEl=document.createElement('div');
    pipelineEl.className='pipeline-progress';
    chatInner.appendChild(pipelineEl);
  }
  let html='<div class="pipeline-header">Verification Pipeline</div><div class="pipeline-nodes">';
  const nodeLabels={PLAN:'Plan',WORKSPACE_INVENTORY:'Scan Files',GENERATE:'Generate',GENERATE_TESTS:'Generate Tests',EXEC_TESTS:'Run Tests',DEPENDENCY_CHECK:'Check Deps',COMPILE:'Compile',REALITY_CHECK:'Reality Check',REPAIR_COMPILE:'Fix Compile',RUN:'Run',REPAIR_RUNTIME:'Fix Runtime',INSPECT:'Inspect',REPAIR_TESTS:'Fix Tests',STATIC_ANALYSIS:'Lint',SELF_REVIEW:'Review',CONSISTENCY:'Consistency',SECURITY:'Security',RED_TEAM:'Red Team',CONFIDENCE:'Confidence',ANSWER:'Done',UNDERSTAND:'Understand',REGRESSION:'Regression',REPAIR_LOGIC:'Fix Logic',REPAIR_SECURITY:'Fix Security'};
  for(const n of p.nodes){
    let icon='○';
    let cls='pending';
    if(n.status==='RUNNING'){icon='◉';cls='running';}
    else if(n.status==='SUCCESS'){icon='✔';cls='success';}
    else if(n.status==='FAILED'){icon='✘';cls='failed';}
    else if(n.status==='SKIPPED'){icon='⊘';cls='skipped';}
    html+='<div class="pipeline-node '+cls+'"><span class="pn-icon">'+icon+'</span><span class="pn-name">'+(nodeLabels[n.id]||n.name)+'</span>';
    if(n.duration)html+='<span class="pn-time">'+n.duration+'s</span>';
    html+='</div>';
  }
  html+='</div>';
  pipelineEl.innerHTML=html;
  chatArea.scrollTop=chatArea.scrollHeight;
}

async function pollPipeline(){
  try{
    const r=await fetch('/pipeline');
    const p=await r.json();
    const pj=JSON.stringify(p);
    if(pj!==lastPipelineJson){lastPipelineJson=pj;renderPipeline(p);}
  }catch(e){}
  setTimeout(pollPipeline,1000);
}

loadChats().then(()=>{
  pollStatus();
  pollThink();
  pollMsgs();
  pollMic();
  pollTTS();
  pollPipeline();
  initResize();
  initHResize();
});

/* ===== Docker Panel: Terminal ===== */
let term=null,termWs=null,termConnected=false,fitAddon=null;

function initTerminal(){
  if(term) {
    fitAddon.fit();
    term.focus();
    return;
  }
  term=new Terminal({
    cursorBlink:true,
    fontSize:13,
    fontFamily:'Cascadia Code,Fira Code,JetBrains Mono,Consolas,monospace',
    theme:{background:'#0d1117',foreground:'#e2e8f0',cursor:'#8b5cf6',selectionBackground:'rgba(139,92,246,0.3)'},
    allowProposedApi:true,
  });
  fitAddon=new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('terminal-container'));
  term.onData(data=>{
    if(termWs&&termWs.readyState===1) termWs.send(data);
  });
  term.onResize(({cols,rows})=>{
    if(termWs&&termWs.readyState===1) termWs.send(JSON.stringify({type:'resize',cols,rows}));
  });
  connectTerminal();
  // Fit after layout settles
  setTimeout(()=>{fitAddon.fit();term.focus()},50);
  setTimeout(()=>{fitAddon.fit();term.focus()},300);
  // Click anywhere in terminal to focus
  document.getElementById('terminal-container').addEventListener('click',()=>{if(term)term.focus();});
}

function connectTerminal(){
  if(termWs&&termWs.readyState<=1) return;
  const wsProto=location.protocol==='https:'?'wss:':'ws:';
  termWs=new WebSocket(wsProto+'//'+location.hostname+':8766');
  termWs.binaryType='arraybuffer';
  termWs.onopen=()=>{
    termConnected=true;
    if(term){term.focus();term.writeln('\\x1b[32m[Connected to container]\\x1b[0m');}
    const {cols,rows}=term;
    termWs.send(JSON.stringify({type:'resize',cols,rows}));
  };
  termWs.onmessage=(e)=>{
    if(term&&e.data){
      const d=typeof e.data==='string'?e.data:new TextDecoder().decode(e.data);
      term.write(d);
    }
  };
  termWs.onclose=()=>{
    termConnected=false;
    if(term) term.writeln('\\r\\n\\x1b[33m[Disconnected from container]\\x1b[0m');
    setTimeout(connectTerminal,3000);
  };
  termWs.onerror=()=>{
    if(term) term.writeln('\\r\\n\\x1b[31m[Connection failed - retrying...]\\x1b[0m');
  };
}

function togglePanel(){
  const panel=document.getElementById('right-panel');
  const btn=document.getElementById('panel-toggle');
  panel.classList.toggle('hidden');
  btn.classList.toggle('active');
  if(!panel.classList.contains('hidden')){
    initTerminal();
    refreshFiles();
  }
}

/* ===== Resize Handle ===== */
function initResize(){
  const handle=document.getElementById('resize-handle');
  const panel=document.getElementById('right-panel');
  let startX,startW;
  handle.addEventListener('mousedown',e=>{
    e.preventDefault();
    startX=e.clientX;
    startW=panel.offsetWidth;
    handle.classList.add('active');
    document.addEventListener('mousemove',onDrag);
    document.addEventListener('mouseup',onUp);
  });
  function onDrag(e){
    const w=Math.max(250,Math.min(800,startW+(startX-e.clientX)));
    panel.style.width=w+'px';
  }
  function onUp(){
    handle.classList.remove('active');
    document.removeEventListener('mousemove',onDrag);
    document.removeEventListener('mouseup',onUp);
    if(term&&fitAddon) fitAddon.fit();
  }
}

/* ===== Horizontal resize between files and terminal ===== */
function initHResize(){
  const handle=document.getElementById('h-resize-handle');
  const termSec=document.getElementById('terminal-section');
  if(!handle||!termSec) return;
  let startY,startH;
  handle.addEventListener('mousedown',e=>{
    e.preventDefault();
    startY=e.clientY;
    startH=termSec.offsetHeight;
    handle.classList.add('active');
    document.addEventListener('mousemove',onDrag);
    document.addEventListener('mouseup',onUp);
  });
  function onDrag(e){
    const h=Math.max(80,Math.min(600,startH+(startY-e.clientY)));
    termSec.style.height=h+'px';
  }
  function onUp(){
    handle.classList.remove('active');
    document.removeEventListener('mousemove',onDrag);
    document.removeEventListener('mouseup',onUp);
    if(term&&fitAddon) fitAddon.fit();
  }
}

/* ===== File Manager ===== */
let currentPath='/workspace';

async function refreshFiles(){
  try{
    const r=await fetch('/files?path='+encodeURIComponent(currentPath));
    const d=await r.json();
    const tree=document.getElementById('file-tree');
    document.getElementById('files-path').textContent=currentPath;
    if(d.error){tree.innerHTML='<div style="padding:12px;color:var(--text3)">'+d.error+'</div>';return;}
    let html='';
    // Up directory button
    if(currentPath!=='/workspace'){
      const upPath=currentPath.split('/').slice(0,-1).join('/')||'/workspace';
      html+='<div class="file-item file-dir" data-path="'+escapeAttr(upPath)+'"><span class="file-icon">&#128193;</span><span class="file-name">..</span></div>';
    }
    // Dirs first, then files
    const dirs=d.entries.filter(e=>e.type==='dir').sort((a,b)=>a.name.localeCompare(b.name));
    const files=d.entries.filter(e=>e.type==='file').sort((a,b)=>a.name.localeCompare(b.name));
    for(const e of dirs){
      if(e.name==='.'||e.name==='..') continue;
      html+='<div class="file-item file-dir" data-path="'+escapeAttr(e.path)+'"><span class="file-icon">&#128193;</span><span class="file-name">'+escapeHtml(e.name)+'</span></div>';
    }
    for(const e of files){
      html+='<div class="file-item" data-path="'+escapeAttr(e.path)+'" data-file="1"><span class="file-icon">&#128196;</span><span class="file-name">'+escapeHtml(e.name)+'</span><span class="file-size">'+(e.size||'')+'</span></div>';
    }
    tree.innerHTML=html||'<div style="padding:12px;color:var(--text3)">Empty directory</div>';
  }catch(e){
    document.getElementById('file-tree').innerHTML='<div style="padding:12px;color:var(--text3)">Cannot connect to container</div>';
  }
}

function escapeAttr(s){return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

document.getElementById('file-tree').addEventListener('click',function(e){
  const item=e.target.closest('.file-item');
  if(!item) return;
  const path=item.getAttribute('data-path');
  if(!path) return;
  if(item.hasAttribute('data-file')) viewFile(path);
  else navigateTo(path);
});

async function navigateTo(path){
  if(path.endsWith('/..')){
    path=path.replace('/..','');
    const parts=path.split('/').filter(Boolean);
    parts.pop();
    path='/' +(parts.join('/')||'');
  }
  currentPath=path;
  await refreshFiles();
}

async function viewFile(path){
  try{
    const r=await fetch('/files/read?path='+encodeURIComponent(path));
    const d=await r.json();
    document.getElementById('file-viewer').style.display='block';
    document.getElementById('file-viewer-name').textContent=path;
    document.getElementById('file-viewer-content').textContent=d.content||'(empty file)';
  }catch(e){}
}

function closeFileViewer(){
  document.getElementById('file-viewer').style.display='none';
}

function detectLang(src){
  if(!src||src.length<10) return null;
  const s=src.trim();
  if(/^\\s*#include\\s*[<\"]/.test(s)){
    if(/\\b(iostream|vector|string|map|set|array|algorithm|memory|fstream|sstream|utility|functional|thread|mutex|chrono|iostream|iomanip|cstdlib|cstring|cassert)\\b/.test(s)) return 'cpp';
    if(/\\b(stdio|stdlib|stdio|math|string|ctype|time|assert|errno|signal|stdarg|stddef|limits)\\.h\\b/.test(s)) return 'c';
    return 'c'; /* default for #include */
  }
  if(/^\\s*import\\s+\\w/.test(s)||/^\\s*from\\s+\\w+\\s+import/.test(s)||/^\\s*def\\s+\\w+\\s*\\(/.test(s)||/^\\s*class\\s+\\w+/.test(s)||/^\\s*print\\s*\\(/.test(s)) return 'python';
  if(/^\\s*const\\s+\\w+\\s*=\\s*(?:require\\s*\\(|function)/.test(s)||/^\\s*(?:let|var|const)\\s+\\w+\\s*=/.test(s)||/^\\s*function\\s+\\w+\\s*\\(/.test(s)||/^\\s*console\\.log/.test(s)) return 'javascript';
  if(/^\\s*fn\\s+\\w+/.test(s)||/^\\s*let\\s+mut\\s+/.test(s)||/^\\s*impl\\s+/.test(s)) return 'rust';
  if(/^\\s*func\\s+\\w+/.test(s)||/^\\s*package\\s+\\w+/.test(s)) return 'go';
  if(/^\\s*class\\s+\\w+.*\\{/.test(s)||/^\\s*public\\s+(?:static\\s+)?void\\s+main/.test(s)) return 'java';
  if(/^\\s*def\\s+main/.test(s)||/^\\s*if\\s+__name__/.test(s)) return 'python';
  if(/^\\s*#!/.test(s)||/^\\s*echo\\s/.test(s)||/^\\s*for\\s+.*\\s+in\\s/.test(s)) return 'bash';
  return null;
}

/* ===== Execute Button on Code Blocks ===== */
function addExecButtons(){
  document.querySelectorAll('.code-block').forEach((block,i)=>{
    const header=block.querySelector('.code-block-header');
    if(!header||header.querySelector('.code-block-exec')) return;
    const langSpan=header.querySelector('.code-block-lang');
    let langText=langSpan?langSpan.textContent.trim():'';
    if(!langText||langText==='diff'||langText==='Output'||langText==='Test Result') return;
    /* Auto-detect language for unlabeled code blocks */
    if(langText==='code'||langText===''){
      const codeEl=block.querySelector('code');
      const src=codeEl?codeEl.textContent:'';
      const detected=detectLang(src);
      if(!detected) return;
      langText=detected;
      if(langSpan) langSpan.textContent=detected;
    }
    const btn=document.createElement('button');
    btn.className='code-block-exec';
    btn.textContent='\u25b6 Run';
    btn.onclick=()=>execCode(i,langText,btn);
    header.insertBefore(btn,header.firstChild);
  });
}

async function execCode(blockId,lang,btn){
  const blocks=document.querySelectorAll('.code-block');
  const block=blocks[blockId];
  if(!block) return;
  const code=block.querySelector('code').textContent;
  btn.textContent='\u23f3 Running...';
  btn.classList.add('running');
  // Open terminal panel
  const panel=document.getElementById('right-panel');
  if(panel.classList.contains('hidden')) togglePanel();
  initTerminal();
  await new Promise(r=>setTimeout(r,300));
  if(!termWs||termWs.readyState!==1){btn.textContent='\u25b6 Run';btn.classList.remove('running');return;}
  // Send commands through visible terminal
  const extMap={c:'.c',cpp:'.cpp','c++':'.cpp',python:'.py',python3:'.py',javascript:'.js',node:'.js',bash:'.sh',shell:'.sh',java:'.java',rust:'.rs',go:'.go'};
  const ext=extMap[lang.toLowerCase()]||extMap[lang]||'.txt';
  const fname='tmp/run'+ext;
  const prog='tmp/run';
  const DELIM='__JARVIS_EOF_12345__';
  // Write file via heredoc (unique delimiter avoids collision with user code)
  const writeCmd='cat > /workspace/'+fname+" << '"+DELIM+"'\\n"+code+"\\n"+DELIM+"\\n";
  termWs.send(writeCmd);
  await new Promise(r=>setTimeout(r,500));
  // Compile if needed
  let compileCmd='';
  if(lang==='c') compileCmd='cd /workspace && gcc -Wall -o '+prog+' '+fname+' 2>tmp/compile_err.txt; echo "JARVIS_COMPILE_EXIT:$?"\\n';
  else if(lang==='cpp'||lang==='c++') compileCmd='cd /workspace && g++ -Wall -o '+prog+' '+fname+' 2>tmp/compile_err.txt; echo "JARVIS_COMPILE_EXIT:$?"\\n';
  else if(lang==='java') compileCmd='cd /workspace && javac '+fname+' 2>tmp/compile_err.txt; echo "JARVIS_COMPILE_EXIT:$?"\\n';
  else if(lang==='rust') compileCmd='cd /workspace && rustc -o '+prog+' '+fname+' 2>tmp/compile_err.txt; echo "JARVIS_COMPILE_EXIT:$?"\\n';
  if(compileCmd){
    termWs.send(compileCmd);
    await new Promise(r=>setTimeout(r,3000));
  }
  // Run command through terminal (visible to user)
  let runCmd='';
  if(lang==='python'||lang==='python3') runCmd='cd /workspace && python3 '+fname+' 2>&1\\n';
  else if(lang==='javascript'||lang==='js'||lang==='node') runCmd='cd /workspace && node '+fname+' 2>&1\\n';
  else if(lang==='bash'||lang==='sh'||lang==='shell') runCmd='cd /workspace && bash '+fname+' 2>&1\\n';
  else if(lang==='java') runCmd='cd /workspace && java -cp . pipeline_run 2>&1\\n';
  else if(lang==='c'||lang==='cpp'||lang==='c++') runCmd='cd /workspace && ./tmp/run 2>&1\\n';
  else if(lang==='rust') runCmd='cd /workspace && ./tmp/run 2>&1\\n';
  else if(lang==='go') runCmd='cd /workspace && ./tmp/run 2>&1\\n';
  if(runCmd){
    termWs.send(runCmd);
    await new Promise(r=>setTimeout(r,500));
  }
  // Also get output via /run endpoint for the badge
  let d={code:0,output:'',warnings:''};
  try{
    const r=await fetch('/run?lang='+encodeURIComponent(lang)+'&code='+encodeURIComponent(code));
    d=await r.json();
  }catch(e){}
  // Show badge
  const existing=block.parentNode.querySelector('.exec-result');
  if(existing) existing.remove();
  const badge=document.createElement('div');
  const ok=d.code===0;
  badge.className='exec-result '+(ok?'success':'error');
  let html='<div class="exec-code">'+(ok?'\u2714 Exit code: 0':'\u2718 Exit code: '+d.code)+'</div>';
  if(d.warnings) html+='<div class="exec-warnings">'+escapeHtml(d.warnings).substring(0,2000)+'</div>';
  if(d.output) html+='<div class="exec-output">'+escapeHtml(d.output).substring(0,3000)+'</div>';
  badge.innerHTML=html;
  block.parentNode.insertBefore(badge,block.nextSibling);
  if(d.code!==0||d.warnings){
    // Show manual Fix button instead of auto-triggering
    const fixBtn=document.createElement('button');
    fixBtn.className='exec-btn';
    fixBtn.textContent='\u2728 Fix';
    fixBtn.onclick=async()=>{
      let fixMsg='Fix the error in the LAST code block I shared. Do NOT rewrite or restructure the code. Only fix the specific error. ';
      if(d.warnings) fixMsg+='Warnings: '+d.warnings.replace(/\\n/g,' ')+' ';
      if(d.code!==0&&d.output) fixMsg+='Errors: '+d.output.replace(/\\n/g,' ')+' ';
      fixMsg+='Give me the COMPLETE fixed code keeping the original structure and logic intact.';
      try{
        fixBtn.textContent='Fixing...';
        fixBtn.disabled=true;
        const fr=await fetch('/autofix?text='+encodeURIComponent(fixMsg));
        const fd=await fr.json();
        if(fd.ok) await loadMsgs();
      }catch(e){}
      fixBtn.textContent='\u2728 Fix';
      fixBtn.disabled=false;
    };
    badge.appendChild(fixBtn);
  }
  btn.textContent='\u25b6 Run';
  btn.classList.remove('running');
}

/* Observe DOM for new code blocks to add exec buttons */
const execObserver=new MutationObserver(()=>addExecButtons());
execObserver.observe(document.getElementById('chat-inner'),{childList:true,subtree:true});

/* ── Settings Modal ── */
function openSettings(){
  document.getElementById('settings-overlay').classList.add('open');
  loadSettings();
}
function closeSettings(){
  document.getElementById('settings-overlay').classList.remove('open');
}
async function loadSettings(){
  try{
    let r=await fetch('/settings');
    let cfg=await r.json();
    document.getElementById('s-mic').value=cfg.mic_device||'';
    document.getElementById('s-model').value=cfg.ollama_model||'mistral';
    document.getElementById('s-model').dataset.saved=cfg.ollama_model||'mistral';
    document.getElementById('s-whisper').value=cfg.whisper_model||'base.en';
    document.getElementById('s-energy').value=cfg.energy_threshold||500;
    document.getElementById('s-energy-val').textContent=cfg.energy_threshold||500;
    document.getElementById('s-nospeech').value=cfg.no_speech_threshold||0.5;
    document.getElementById('s-nospeech-val').textContent=(cfg.no_speech_threshold||0.5).toFixed(2);
    document.getElementById('s-segment').value=cfg.min_segment_duration||1.0;
    document.getElementById('s-segment-val').textContent=(cfg.min_segment_duration||1.0).toFixed(1)+'s';
    document.getElementById('s-vad').value=cfg.vad_aggressiveness||3;
    document.getElementById('s-vad-val').textContent=cfg.vad_aggressiveness||3;
    document.getElementById('s-ttsspeed').value=cfg.tts_speed||1.0;
    document.getElementById('s-ttsspeed-val').textContent=(cfg.tts_speed||1.0).toFixed(1)+'x';
    document.getElementById('s-numctx').value=cfg.num_ctx||4096;
    document.getElementById('s-numctx-val').textContent=(cfg.num_ctx||4096).toLocaleString();
    document.getElementById('s-autostart').checked=cfg.auto_start!==false;
    if(cfg.preview_text)document.getElementById('s-preview-text').value=cfg.preview_text;
    /* populate dropdowns -- pass saved values so they can set after fetching */
    loadMics(); loadVoices(cfg.tts_voice); loadModels();
  }catch(e){}
}
async function loadMics(){
  try{
    let r=await fetch('/settings/mics');
    let d=await r.json();
    let sel=document.getElementById('s-mic');
    let cur=sel.value;
    sel.innerHTML='';
    let matched=false;
    d.mics.forEach(m=>{let o=document.createElement('option');o.value=m;o.textContent=m;if(m===cur){o.selected=true;matched=true;}sel.appendChild(o);});
    if(!matched&&d.default){sel.value=d.default;}
  }catch(e){}
}
async function loadVoices(saved){
  try{
    let r=await fetch('/settings/voices');
    let d=await r.json();
    let sel=document.getElementById('s-voice');
    let cur=saved||sel.value;
    sel.innerHTML='';
    let matched=false;
    d.voices.forEach(v=>{let o=document.createElement('option');o.value=v.name;o.textContent=v.name+' ('+v.gender+')';if(v.name===cur){o.selected=true;matched=true;}sel.appendChild(o);});
    if(!matched&&cur)sel.value=cur;
  }catch(e){}
}
async function loadModels(){
  try{
    let r=await fetch('/settings/models');
    let d=await r.json();
    let sel=document.getElementById('s-model');
    let cur=sel.value||document.getElementById('s-model').dataset.saved||'';
    sel.innerHTML='';
    let matched=false;
    d.models.forEach(m=>{let o=document.createElement('option');o.value=m;o.textContent=m+(m.startsWith('mistral')?' (Recommended)':'');if(m===cur){o.selected=true;matched=true;}sel.appendChild(o);});
    if(!matched&&d.models.length){sel.value=d.models[0];}
    if(!d.models.length){let o=document.createElement('option');o.textContent='No models found';sel.appendChild(o);}
  }catch(e){}
}
let _previewAudio=null;
let _previewController=null;
function onVoiceChange(){
  if(_previewAudio){_previewAudio.pause();_previewAudio=null;}
  if(_previewController){_previewController.abort();_previewController=null;}
  let voice=document.getElementById('s-voice').value;
  let text=document.getElementById('s-preview-text').value.trim();
  if(!text||!voice)return;
  _previewController=new AbortController();
  let url='/tts/preview?voice='+encodeURIComponent(voice)+'&text='+encodeURIComponent(text)+'&speed='+encodeURIComponent(document.getElementById('s-ttsspeed').value);
  fetch(url,{signal:_previewController.signal}).then(r=>r.blob()).then(blob=>{
    let audio=new Audio(URL.createObjectURL(blob));
    _previewAudio=audio;
    audio.onended=()=>{_previewAudio=null;};
    audio.play().catch(()=>{});
  }).catch(()=>{});
}
function savePreviewText(){
  let text=document.getElementById('s-preview-text').value;
  let params=new URLSearchParams();
  params.set('preview_text',text);
  fetch('/settings/save?'+params.toString()).then(()=>{
    let btn=event.target;btn.textContent='Saved!';
    setTimeout(()=>{btn.textContent='Save Text';},1500);
  });
}
async function saveSettings(){
  let params=new URLSearchParams();
  params.set('mic_device',document.getElementById('s-mic').value);
  params.set('tts_voice',document.getElementById('s-voice').value);
  params.set('ollama_model',document.getElementById('s-model').value);
  params.set('whisper_model',document.getElementById('s-whisper').value);
  params.set('energy_threshold',document.getElementById('s-energy').value);
  params.set('no_speech_threshold',document.getElementById('s-nospeech').value);
  params.set('min_segment_duration',document.getElementById('s-segment').value);
  params.set('vad_aggressiveness',document.getElementById('s-vad').value);
  params.set('tts_speed',document.getElementById('s-ttsspeed').value);
  params.set('num_ctx',document.getElementById('s-numctx').value);
  params.set('auto_start',document.getElementById('s-autostart').checked);
  params.set('preview_text',document.getElementById('s-preview-text').value);
  await fetch('/settings/save?'+params.toString());
  closeSettings();
}
</script>
<div class="modal-overlay" id="settings-overlay" onclick="if(event.target===this)closeSettings()">
<div class="modal">
  <h2>Settings</h2>

  <h3>Audio Input</h3>
  <label>Microphone</label>
  <select id="s-mic"></select>
  <label>Energy Threshold</label>
  <div class="range-row"><input type="range" id="s-energy" min="50" max="5000" step="50" oninput="document.getElementById('s-energy-val').textContent=this.value"><span class="range-val" id="s-energy-val">500</span></div>
  <label>VAD Aggressiveness (1=least, 3=most)</label>
  <div class="range-row"><input type="range" id="s-vad" min="1" max="3" step="1" oninput="document.getElementById('s-vad-val').textContent=this.value"><span class="range-val" id="s-vad-val">3</span></div>

  <h3>Audio Output</h3>
  <label>TTS Voice</label>
  <select id="s-voice" onchange="onVoiceChange()"></select>
  <label>Preview Message</label>
  <input type="text" id="s-preview-text" value="Hello, I'm Jarvis. How can I help you today?" placeholder="Preview text..." style="width:100%;box-sizing:border-box">
  <div class="preview-row">
    <button class="btn-preview" onclick="onVoiceChange()">Play</button>
    <button class="btn-preview btn-reset" onclick="document.getElementById('s-preview-text').value='Hello, I\\'m Jarvis. How can I help you today?'">Reset</button>
    <span style="flex:1"></span>
    <button class="btn-preview" onclick="savePreviewText()">Save Text</button>
  </div>
  <label>TTS Speed</label>
  <div class="range-row"><input type="range" id="s-ttsspeed" min="0.5" max="2.0" step="0.1" oninput="document.getElementById('s-ttsspeed-val').textContent=parseFloat(this.value).toFixed(1)+'x'"><span class="range-val" id="s-ttsspeed-val">1.0x</span></div>

  <h3>Whisper</h3>
  <label>Model Size</label>
  <select id="s-whisper">
    <option value="tiny.en">tiny.en (fastest)</option>
    <option value="base.en" selected>base.en (default)</option>
    <option value="small.en">small.en</option>
    <option value="medium.en">medium.en</option>
  </select>
  <label>No-Speech Threshold</label>
  <div class="range-row"><input type="range" id="s-nospeech" min="0.1" max="0.9" step="0.05" oninput="document.getElementById('s-nospeech-val').textContent=parseFloat(this.value).toFixed(2)"><span class="range-val" id="s-nospeech-val">0.50</span></div>
  <label>Min Segment Duration (seconds)</label>
  <div class="range-row"><input type="range" id="s-segment" min="0.5" max="3.0" step="0.1" oninput="document.getElementById('s-segment-val').textContent=parseFloat(this.value).toFixed(1)+'s'"><span class="range-val" id="s-segment-val">1.0s</span></div>

  <h3>LLM</h3>
  <label>Ollama Model</label>
  <select id="s-model"></select>
  <label>Context Window (tokens)</label>
  <div class="range-row"><input type="range" id="s-numctx" min="2048" max="32768" step="1024" oninput="document.getElementById('s-numctx-val').textContent=parseInt(this.value).toLocaleString()"><span class="range-val" id="s-numctx-val">4,096</span></div>

  <h3>System</h3>
  <div class="toggle-row">
    <label>Auto-start on boot</label>
    <label class="toggle"><input type="checkbox" id="s-autostart"><span class="slider"></span></label>
  </div>

  <div class="modal-actions">
    <button class="btn-cancel" onclick="closeSettings()">Cancel</button>
    <button class="btn-save" onclick="saveSettings()">Save</button>
  </div>
</div>
</div>
</body>
</html>"""


if __name__ == "__main__":
    import gc
    print(f"Jarvis Web UI at http://localhost:{PORT}")

    def _mem_watchdog():
        """Restart if RSS exceeds 1 GB — ThreadingHTTPServer leaks thread stacks."""
        import time as _t
        while True:
            _t.sleep(60)
            try:
                with open(f"/proc/{os.getpid()}/status") as _f:
                    for _line in _f:
                        if _line.startswith("VmRSS:"):
                            rss_kb = int(_line.split()[1])
                            if rss_kb > 1_048_576:  # 1 GB
                                print(f"[webui] RSS {rss_kb//1024}MB > 1GB, restarting", flush=True)
                                os._exit(1)
                            break
            except Exception:
                pass

    threading.Thread(target=_mem_watchdog, daemon=True).start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
