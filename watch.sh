#!/bin/bash
JARVIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILE="$JARVIS_DIR/voice_command.txt"
LAST=""
while true; do
    if [ -f "$FILE" ]; then
        CONTENT=$(cat "$FILE")
        if [ "$CONTENT" != "$LAST" ] && [ -n "$CONTENT" ]; then
            echo "$(date '+%H:%M:%S') - $CONTENT" >> "$JARVIS_DIR/transcript.log"
            LAST="$CONTENT"
        fi
    fi
    sleep 1
done
