#!/bin/bash
# Jarvis launcher — auto-detects project directory, works from any location
LOCKFILE="/tmp/jarvis_autostart.lock"
exec 200>"$LOCKFILE"
flock -n 200 || exit 1

# ── Auto-detect project directory from script location ────────────────
JARVIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$JARVIS_DIR"

VENV_PYTHON="$JARVIS_DIR/venv/bin/python"
if [ ! -f "$VENV_PYTHON" ]; then
    VENV_PYTHON="$(which python3)"
fi

# ── Optional: Fix ALSA Auto-Mute getting stuck on reboot ─────────────
sleep 2
if command -v amixer >/dev/null 2>&1; then
    amixer -c 1 cset name='Auto-Mute Mode' Disabled >/dev/null 2>&1
fi

$VENV_PYTHON "$JARVIS_DIR/jarv2.py" &
JARVIS_PID=$!

sleep 2
bash "$JARVIS_DIR/auto_responder.sh" &
RESPONDER_PID=$!

$VENV_PYTHON "$JARVIS_DIR/webui.py" &
WEBUI_PID=$!

$VENV_PYTHON "$JARVIS_DIR/ws_server.py" &
WS_PID=$!

# ── Hyprland env setup (optional — skip if not on Hyprland) ──────────
if command -v hyprctl >/dev/null 2>&1; then
    for i in $(seq 1 30); do
        hyprctl monitors >/dev/null 2>&1 && break
        sleep 1
    done

    # Detect current user UID dynamically
    CURRENT_UID=$(id -u)

    HISIG=$(ls "/run/user/$CURRENT_UID/hypr/" 2>/dev/null | head -1)
    if [ -n "$HISIG" ]; then
        export HYPRLAND_INSTANCE_SIGNATURE="$HISIG"
    fi
    WAYLAND_SOCK=$(ls "/run/user/$CURRENT_UID/wayland-"* 2>/dev/null | head -1)
    if [ -n "$WAYLAND_SOCK" ]; then
        export WAYLAND_DISPLAY=$(basename "$WAYLAND_SOCK")
    fi
    export XDG_RUNTIME_DIR="/run/user/$CURRENT_UID"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$CURRENT_UID/bus"
    [ -z "$DISPLAY" ] && export DISPLAY=:0
fi

# ── Greeting logic ────────────────────────────────────────────────────
TS=$(date '+%H:%M:%S')
JARVIS_DATA="$HOME/.local/share/jarvis"
mkdir -p "$JARVIS_DATA/chats"
ACTIVE_CHAT=$(cat "$JARVIS_DATA/active_chat" 2>/dev/null)
BOOT_TIME=$(awk '/^btime/{print $2}' /proc/stat)

if [ -n "$ACTIVE_CHAT" ] && [ -f "$JARVIS_DATA/chats/${ACTIVE_CHAT}.log" ]; then
    CHAT_MTIME=$(stat -c %Y "$JARVIS_DATA/chats/${ACTIVE_CHAT}.log" 2>/dev/null || echo 0)
    if [ "$BOOT_TIME" -le "$CHAT_MTIME" ]; then
        echo "[$TS] [Jarvis] Jarvis restarted. Resuming previous chat." >> "$JARVIS_DATA/chats/${ACTIVE_CHAT}.log"
        echo "Jarvis restarted. Resuming previous chat." > "$JARVIS_DIR/response.txt"
    elif [ "$(date -d @$CHAT_MTIME +%Y-%m-%d)" = "$(date +%Y-%m-%d)" ]; then
        echo "[$TS] [Jarvis] Jarvis is back online. Continuing where we left off." >> "$JARVIS_DATA/chats/${ACTIVE_CHAT}.log"
        echo "Jarvis is back online. Continuing where we left off." > "$JARVIS_DIR/response.txt"
    else
        NEW_ID=$(python3 -c "import uuid; print(uuid.uuid4().hex[:12])")
        echo "[$TS] [Jarvis] Hey! Jarvis is back online. What can I do for you?" > "$JARVIS_DATA/chats/${NEW_ID}.log"
        echo "$NEW_ID" > "$JARVIS_DATA/active_chat"
        echo "Hey! Jarvis is back online. What can I do for you?" > "$JARVIS_DIR/response.txt"
    fi
else
    NEW_ID=$(python3 -c "import uuid; print(uuid.uuid4().hex[:12])")
    echo "[$TS] [Jarvis] Hey! Jarvis is back online. What can I do for you?" > "$JARVIS_DATA/chats/${NEW_ID}.log"
    echo "$NEW_ID" > "$JARVIS_DATA/active_chat"
    echo "Hey! Jarvis is back online. What can I do for you?" > "$JARVIS_DIR/response.txt"
fi

# ── Wait for webui, then open in browser ──────────────────────────────
for i in $(seq 1 30); do
    if curl -s http://localhost:8765 | grep -q "Jarvis" 2>/dev/null; then
        break
    fi
    sleep 1
done

if command -v hyprctl >/dev/null 2>&1; then
    hyprctl dispatch focusmonitor HDMI-A-1 2>/dev/null
fi
sleep 0.5
/usr/bin/firefox -P default --new-window http://localhost:8765 &
FIREFOX_PID=$!

# ── Monitor loop: restart crashed components ──────────────────────────
RUNNING=1
cleanup() {
    RUNNING=0
    if [ -n "$RESPONDER_PID" ] && kill -0 "$RESPONDER_PID" 2>/dev/null; then
        pkill -P "$RESPONDER_PID" 2>/dev/null
        kill "$RESPONDER_PID" 2>/dev/null
    fi
    kill $FIREFOX_PID 2>/dev/null
    kill $WS_PID 2>/dev/null
    kill $WEBUI_PID 2>/dev/null
    kill $JARVIS_PID 2>/dev/null
    wait 2>/dev/null
}
trap cleanup SIGINT SIGTERM

while [ "$RUNNING" = "1" ]; do
    if ! kill -0 $WEBUI_PID 2>/dev/null; then
        echo "[$(date '+%H:%M:%S')] webui died, restarting..."
        $VENV_PYTHON "$JARVIS_DIR/webui.py" >> /tmp/webui.log 2>&1 &
        WEBUI_PID=$!
    fi
    if ! kill -0 $JARVIS_PID 2>/dev/null; then
        echo "[$(date '+%H:%M:%S')] jarv2 died, restarting..."
        $VENV_PYTHON "$JARVIS_DIR/jarv2.py" >> /tmp/jarv2.log 2>&1 &
        JARVIS_PID=$!
    fi
    sleep 5
done
