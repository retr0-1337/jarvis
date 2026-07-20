"""Jarvis configuration — all paths and settings in one place.

Every path in the project should be derived from PROJECT_DIR here.
Network/device settings can be overridden via environment variables.
"""
import json
import os
from pathlib import Path

# ── Core paths (auto-detected from this file's location) ──────────────
PROJECT_DIR = Path(__file__).parent.resolve()
SECURITY_DB_DIR = PROJECT_DIR / "security_db"
WORKSPACE_DIR = PROJECT_DIR / "workspace"

# ── Runtime IPC files (inside project dir) ────────────────────────────
TRANSCRIPT_FILE = PROJECT_DIR / "transcript.txt"
RESPONSE_FILE = PROJECT_DIR / "response.txt"
CONV_LOG = PROJECT_DIR / "conversation.log"
VOICE_COMMAND_FILE = PROJECT_DIR / "voice_command.txt"

# ── User data (~/.local/share/jarvis) ─────────────────────────────────
DATA_DIR = Path(os.environ.get("JARVIS_DATA_DIR", Path.home() / ".local" / "share" / "jarvis"))
CHATS_DIR = DATA_DIR / "chats"
ACTIVE_CHAT_FILE = DATA_DIR / "active_chat"

# ── User config (~/.config/jarvis) ────────────────────────────────────
CONFIG_DIR = Path(os.environ.get("JARVIS_CONFIG_DIR", Path.home() / ".config" / "jarvis"))
CONFIG_FILE = CONFIG_DIR / "settings.json"

# ── Network / device settings (override via env vars) ─────────────────
PI_HOST = os.environ.get("JARVIS_PI_HOST", "192.168.0.111")
PI_USER = os.environ.get("JARVIS_PI_USER", "pi")
PI_CAMERA_URL = os.environ.get("JARVIS_PI_CAMERA_URL", f"http://{PI_HOST}:5000")

# ── Metasploit ────────────────────────────────────────────────────────
MSF_PATH = os.environ.get("JARVIS_MSF_PATH", "/opt/metasploit/modules/exploits")

# ── CUDA (optional, for faster-whisper GPU) ──────────────────────────
CUDA_LIB = os.environ.get("JARVIS_CUDA_LIB", "")

# ── Ensure runtime directories exist ──────────────────────────────────
CHATS_DIR.mkdir(parents=True, exist_ok=True)

# ── Settings (persisted user preferences) ─────────────────────────────
DEFAULTS = {
    "mic_device": "pipewire",
    "tts_voice": "en-US-SteffanNeural",
    "ollama_model": "mistral",
    "whisper_model": "base.en",
    "energy_threshold": 500,
    "no_speech_threshold": 0.5,
    "min_segment_duration": 1.0,
    "vad_aggressiveness": 3,
    "tts_speed": 1.0,
    "num_ctx": 4096,
    "auto_start": True,
    "preview_text": "Hello, I'm Jarvis. How can I help you today?",
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in DEFAULTS.items():
            cfg.setdefault(k, v)
        return cfg
    return dict(DEFAULTS)


def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def get(key: str):
    return load_config().get(key, DEFAULTS.get(key))


def set(key: str, value):
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)
