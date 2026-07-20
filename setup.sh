#!/bin/bash
# Jarvis AI Assistant — Installer
# Sets up Python venv, installs dependencies, and creates config.
set -e

JARVIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$JARVIS_DIR"

echo "╔══════════════════════════════════════╗"
echo "║       Jarvis AI Assistant Setup      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Python venv ────────────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "[1/4] Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "[1/4] Virtual environment already exists."
fi

source venv/bin/activate

# ── 2. pip dependencies ──────────────────────────────────────────────
echo "[2/4] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# ── 3. Ollama models ─────────────────────────────────────────────────
echo "[3/4] Checking Ollama..."
if command -v ollama >/dev/null 2>&1; then
    echo "       Ollama found. Pulling models (this may take a while)..."
    ollama pull mistral 2>/dev/null || echo "       (skipped — pull manually with: ollama pull mistral)"
else
    echo "       Ollama not found. Install it from: https://ollama.com"
    echo "       Then run: ollama pull mistral"
fi

# ── 4. Config file ───────────────────────────────────────────────────
echo "[4/4] Setting up config..."
mkdir -p ~/.config/jarvis
if [ ! -f ~/.config/jarvis/settings.json ]; then
    cat > ~/.config/jarvis/settings.json << 'EOF'
{
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
  "auto_start": true
}
EOF
    echo "       Config created at ~/.config/jarvis/settings.json"
else
    echo "       Config already exists."
fi

# ── 5. Runtime directories ────────────────────────────────────────────
mkdir -p ~/.local/share/jarvis/chats

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║           Setup Complete!            ║"
echo "╠══════════════════════════════════════╣"
echo "║                                      ║"
echo "║  Start Jarvis:                       ║"
echo "║    bash start_jarvis.sh              ║"
echo "║                                      ║"
echo "║  Or run individual components:       ║"
echo "║    source venv/bin/activate          ║"
echo "║    python webui.py    (web UI)       ║"
echo "║    python jarv2.py    (voice)        ║"
echo "║                                      ║"
echo "║  Web UI: http://localhost:8765       ║"
echo "║                                      ║"
echo "║  Optional env vars:                  ║"
echo "║    JARVIS_PI_HOST=192.168.1.100      ║"
echo "║    JARVIS_PI_USER=pi                 ║"
echo "║    JARVIS_MSF_PATH=/opt/metasploit   ║"
echo "║    JARVIS_CUDA_LIB=/usr/local/cuda   ║"
echo "║                                      ║"
echo "╚══════════════════════════════════════╝"
