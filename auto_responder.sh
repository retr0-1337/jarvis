#!/bin/bash
LOCKFILE="/tmp/auto_responder.lock"
exec 200>"$LOCKFILE"
flock -n 200 || { echo "Another instance already running"; exit 1; }

# ── Auto-detect project directory from script location ────────────────
JARVIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRANSCRIPT="$JARVIS_DIR/transcript.txt"
RESPONSE="$JARVIS_DIR/response.txt"
CONV_LOG="$JARVIS_DIR/conversation.log"
ACTIVE_CHAT_DIR="$HOME/.local/share/jarvis/chats"
ACTIVE_CHAT_FILE="$HOME/.local/share/jarvis/active_chat"

# ── Network config (override via env vars) ────────────────────────────
PI_HOST="${JARVIS_PI_HOST:-192.168.0.111}"
PI_USER="${JARVIS_PI_USER:-pi}"
PI_CAMERA_URL="${JARVIS_PI_CAMERA_URL:-http://$PI_HOST:5000}"
PI_SSH="ssh -o StrictHostKeyChecking=no $PI_USER@$PI_HOST"
PI_HOME="${JARVIS_PI_HOME:-/home/$PI_USER}"

LAST_LINE=$(tail -1 "$TRANSCRIPT" 2>/dev/null)

# Stop word detection: "stop", "interrupt", "cancel", "nevermind", "leave it"
_trimmed=$(echo "$LAST_LINE" | sed 's/^\[.*\] //' | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if echo "$_trimmed" | grep -qxE '(stop|interrupt|cancel|nevermind|never mind|leave it|enough|cease|quit)'; then
    # Abort pipeline if running
    touch /tmp/jarvis_pipeline_abort
    # Stop TTS
    if [ -f "$RESPONSE" ]; then
        echo "" > "$RESPONSE"
    fi
    echo "" > /tmp/jarvis_status.txt
    echo "" > /tmp/jarvis_thinking.txt
    # Clear transcript so stop word isn't processed
    echo "" > "$TRANSCRIPT"
    exit 0
fi

# Write to both conversation.log and active chat log
# $1 = message, $2 = optional chat ID override (used when processing started in a different chat)
 write_response() {
    local override_chat="$1"
    local msg="$2"
    local ts=$(date '+%H:%M:%S')
    local tagged="[$ts] $msg"
    echo "$tagged" >> "$CONV_LOG"
    # Use override chat ID if provided, otherwise read current active
    local chat_id="$override_chat"
    if [ -z "$chat_id" ] && [ -f "$ACTIVE_CHAT_FILE" ]; then
        chat_id=$(cat "$ACTIVE_CHAT_FILE" 2>/dev/null)
    fi
    if [ -n "$chat_id" ] && [ -f "$ACTIVE_CHAT_DIR/${chat_id}.log" ]; then
        echo "$tagged" >> "$ACTIVE_CHAT_DIR/${chat_id}.log"
        local json_file="$ACTIVE_CHAT_DIR/${chat_id}.json"
        if [ -f "$json_file" ]; then
            local response_text="${msg#"[Jarvis] "}"
            response_text="${response_text#Jarvis: }"
            local edit_idx=""
            if [ -f /tmp/jarvis_edit_idx ]; then
                edit_idx=$(cat /tmp/jarvis_edit_idx 2>/dev/null)
                rm -f /tmp/jarvis_edit_idx
            fi
            python3 -c "
import json, sys
with open('$json_file') as f: d=json.load(f)
if d['messages']:
    idx = int(sys.argv[2]) if sys.argv[2] else len(d['messages']) - 1
    idx = max(0, min(idx, len(d['messages']) - 1))
    d['messages'][idx].setdefault('responses', [])
    d['messages'][idx]['responses'].append({'text': sys.argv[1], 'ts': '$ts'})
    with open('$json_file','w') as f: json.dump(d,f,indent=2)
" "$response_text" "$edit_idx" 2>/dev/null
        fi
    fi
}

while true; do
    if [ -f "$TRANSCRIPT" ]; then
        # Process ALL lines since last processed (not just tail -1)
        # This ensures short commands aren't lost during long pipelines
        if [ -z "$LAST_LINE" ]; then
            PENDING_LINES=$(cat "$TRANSCRIPT" 2>/dev/null)
        else
            PENDING_LINES=$(awk -v last="$LAST_LINE" 'found; $0 == last {found=1}' "$TRANSCRIPT" 2>/dev/null)
        fi
        if [ -z "$PENDING_LINES" ]; then
            sleep 1
            continue
        fi
        while IFS= read -r CURRENT; do
            [ -z "$CURRENT" ] && continue
            # Parse source tag: [voice] or [text]
            SOURCE="text"
            if echo "$CURRENT" | grep -q '\[voice\]'; then
                SOURCE="voice"
            fi
            TEXT=$(echo "$CURRENT" | sed 's/^\[.*\] //' | sed 's/^\[voice\] //; s/^\[text\] //')
            TIMESTAMP_RAW=$(echo "$CURRENT" | grep -oP '^\[\K[^\]]+')
            # Capture the active chat ID at processing start — responses go here even if active changes
            PROCESS_CHAT_ID=""
            if [ -f "$ACTIVE_CHAT_FILE" ]; then
                PROCESS_CHAT_ID=$(cat "$ACTIVE_CHAT_FILE" 2>/dev/null)
            fi
            echo "[Auto] Processing: $TEXT"

            # Skip if text matches common TTS phrases (echo protection)
            LOWERCASE=$(echo "$TEXT" | tr '[:upper:]' '[:lower:]')
            WORD_COUNT=$(echo "$LOWERCASE" | wc -w)
            case "$LOWERCASE" in
                "paused"|"playing"|"skipped"|"going back"|"resumed"|"camera snapshot"|"live camera feed"|"you're welcome"*|"camera fps changed"*)
                    echo "[Auto] Skipping TTS echo: $TEXT"
            LAST_LINE="$CURRENT"
            if [ -f "$ACTIVE_CHAT_FILE" ]; then
                CHAT_ID=$(cat "$ACTIVE_CHAT_FILE" 2>/dev/null)
                if [ -n "$CHAT_ID" ] && [ -f "$ACTIVE_CHAT_DIR/${CHAT_ID}.log" ]; then
                    cd "$JARVIS_DIR" && source venv/bin/activate && python3 rag.py index-new "$ACTIVE_CHAT_DIR/${CHAT_ID}.log" >/dev/null 2>&1 &
                fi
            fi
                    continue ;;
            esac
            # Short messages (<=4 words) are voice commands; longer ones go straight to Ollama
            if [ "$WORD_COUNT" -gt 4 ]; then
                THINKING_FILE="/tmp/jarvis_thinking.txt"
                TMP_OUT="/tmp/jarvis_output.txt"
                : > "$THINKING_FILE"
                : > "$TMP_OUT"
                echo "1" > /tmp/jarvis_status.txt
                echo "" > "$RESPONSE"
                echo "Processing..." > "$THINKING_FILE"
                # Pre-check: skip pipeline if chat was already deleted
                if [ -n "$PROCESS_CHAT_ID" ] && [ ! -f "$ACTIVE_CHAT_DIR/${PROCESS_CHAT_ID}.json" ]; then
                    echo "[Auto] Chat $PROCESS_CHAT_ID deleted — skipping pipeline"
                    LAST_LINE="$CURRENT"
                    continue
                fi
                ESCAPED=$(printf '%s' "$TEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')
                OUTPUT=$(cd "$JARVIS_DIR" && source venv/bin/activate && python3 ask.py "$ESCAPED" --source "$SOURCE" --chat-id "$PROCESS_CHAT_ID" 2>/tmp/jarvis_ask_error.log)
                # Post-check: if chat was deleted during pipeline, discard response
                if [ -n "$PROCESS_CHAT_ID" ] && [ ! -f "$ACTIVE_CHAT_DIR/${PROCESS_CHAT_ID}.json" ]; then
                    echo "[Auto] Chat $PROCESS_CHAT_ID deleted during pipeline — discarding response"
                    LAST_LINE="$CURRENT"
                    continue
                fi
                if [ -z "$OUTPUT" ]; then
                    OUTPUT="I didn't catch that — could you try again?"
                fi
                # Handle special command responses
                case "$OUTPUT" in
                    __STOP_TTS__)
                        pkill -f "edge-tts\|gtts-cli\|tts" 2>/dev/null
                        echo "0" > /tmp/jarvis_status.txt
                        LAST_LINE="$CURRENT"
                        continue ;;
                    __SHOW_CAMERA__)
                        OUTPUT="<img src=\"${PI_CAMERA_URL}/video_feed\" style=\"width:100%;border-radius:6px;\" />"
                        echo "$OUTPUT" > "$THINKING_FILE"
                        ;;
                esac
                write_response "$PROCESS_CHAT_ID" "[Jarvis] $OUTPUT"
                # Strip HTML, pipeline metadata, and code blocks for TTS
                # If response has a <!--TTS:...--> marker, use just that text
                if echo "$OUTPUT" | grep -q '<!--TTS:'; then
                    SPOKEN=$(echo "$OUTPUT" | sed -n 's/.*<!--TTS:\(.*\)-->.*$/\1/p')
                else
                SPOKEN=$(echo "$OUTPUT" \
                    | sed 's/<\(img\|video\)[^>]*>//g; s/<\/\(img\|video\)>//g' \
                    | sed '/^```/,/^```/d' \
                    | sed '/^\*\*File:\*\*/d' \
                    | sed '/^\[ASK\]/d' \
                    | sed '/^Verification /d' \
                    | sed '/^- \*\*Exec Tests\*\*/d' \
                    | sed '/^- \*\*Security\*\*/d' \
                    | sed '/^- \*\*Self Review\*\*/d' \
                    | sed '/^- \*\*Red Team\*\*/d' \
                    | sed '/^- \*\*Inspection\*\*/d' \
                    | sed '/^- \*\*Consistency\*\*/d' \
                    | sed '/^- \*\*Static Analysis\*\*/d' \
                    | sed '/^- \*\*Dependency Check\*\*/d' \
                    | sed '/^Confidence/d' \
                    | sed '/^Exit:/d' \
                    | sed '/^Pass:/d' \
                    | sed '/^Fail:/d' \
                    | sed '/^Test failed:/d' \
                    | sed '/^Test passed:/d' \
                    | sed 's/`[^`]*`//g' \
                    | sed 's/\*\*[^*]*\*\*//g' \
                    | sed '/^[[:space:]]*$/d' \
                    | tr '\n' ' ' | sed 's/  */ /g' | sed 's/^ *//;s/ *$//')
                fi
                echo "$SPOKEN" > "$RESPONSE"
                : > "$THINKING_FILE"
                echo "0" > /tmp/jarvis_status.txt
                # Clear pipeline status so webui doesn't show stale "running"
                rm -f /tmp/jarvis_pipeline.json
                LAST_LINE="$CURRENT"
                continue
            fi
            case "$LOWERCASE" in
                *pause*|*freeze*)
                    playerctl pause 2>/dev/null
                    write_response "$PROCESS_CHAT_ID" "[Jarvis] Paused"
                    echo "Paused" > "$RESPONSE"
                    echo "0" > /tmp/jarvis_status.txt ;;
                *play*|*resume*|*unpause*)
                    # "play <something>" searches youtube; bare "play" resumes
                    PLAYTEXT=$(echo "$TEXT" | sed 's/.*play //i')
                    if [ -n "$PLAYTEXT" ] && [ ${#PLAYTEXT} -gt 2 ] && \
                       [[ "$LOWERCASE" != *resume* ]] && [[ "$LOWERCASE" != *unpause* ]]; then
                        ENCODED=$(echo "$PLAYTEXT" | sed 's/ /+/g')
                        xdg-open "https://youtube.com/results?search_query=$ENCODED" 2>/dev/null &
                        write_response "$PROCESS_CHAT_ID" "[Jarvis] Playing $PLAYTEXT"
                        echo "Playing $PLAYTEXT" > "$RESPONSE"
                    else
                        playerctl play 2>/dev/null
                        write_response "$PROCESS_CHAT_ID" "[Jarvis] Playing"
                        echo "Playing" > "$RESPONSE"
                    fi
                    echo "0" > /tmp/jarvis_status.txt ;;
                *next*|*skip*)
                    playerctl next 2>/dev/null
                    write_response "$PROCESS_CHAT_ID" "[Jarvis] Skipped"
                    echo "Skipped" > "$RESPONSE"
                    echo "0" > /tmp/jarvis_status.txt ;;
                *previous*)
                    playerctl previous 2>/dev/null
                    write_response "$PROCESS_CHAT_ID" "[Jarvis] Going back"
                    echo "Going back" > "$RESPONSE"
                    echo "0" > /tmp/jarvis_status.txt ;;
                *)
                    THINKING_FILE="/tmp/jarvis_thinking.txt"
                    TMP_OUT="/tmp/jarvis_output.txt"
                    : > "$THINKING_FILE"
                    : > "$TMP_OUT"
                    echo "" > "$RESPONSE"
                    # Camera / raspberry pi commands
                    case "$LOWERCASE" in
                        *fps*|*framerate*)
                            FPS=$(echo "$TEXT" | grep -oP '\d+' | head -1)
                            if [ -n "$FPS" ]; then
                                echo "Setting FPS to $FPS..." > "$THINKING_FILE"
                                $PI_SSH \
                                    "sudo sed -i \"s/'--framerate', '[0-9]*'/'--framerate', '$FPS'/\" $PI_HOME/pi-camera-stream-flask/camera.py && sudo kill \$(ps aux | grep -v 'bash -c' | grep -E '[p]ython3.*pi-camera-stream-flask|[r]picam-vid' | awk '{print \$2}') 2>/dev/null; sleep 3; sudo setsid /usr/bin/python3 $PI_HOME/pi-camera-stream-flask/main.py >> /tmp/camera_log.txt 2>&1 &" 2>/dev/null
                                sleep 5
                                timeout 3 curl -s "${PI_CAMERA_URL}/video_feed" > /dev/null 2>&1
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Camera FPS changed to $FPS"
                                echo "Camera FPS changed to $FPS" > "$RESPONSE"
                            else
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Tell me what FPS value"
                                echo "Tell me what FPS value" > "$RESPONSE"
                            fi
                            echo "0" > /tmp/jarvis_status.txt
                            ;;
                        *stream*|*feed*)
                            CAM_IMG="<img src=\"${PI_CAMERA_URL}/video_feed\" style=\"width:100%;border-radius:6px;\" />"
                            echo "$CAM_IMG" > "$THINKING_FILE"
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] $CAM_IMG"
                            echo "" > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt
                            ;;
                        *snapshot*|*snap*|*photo*|*picture*)
                            CAM_IMG="<img src=\"${PI_CAMERA_URL}/snapshot\" style=\"width:100%;border-radius:6px;\">"
                            echo "$CAM_IMG" > "$THINKING_FILE"
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] $CAM_IMG"
                            echo "" > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt
                            ;;
                        *camera*|*look*|*check*)
                            CAM_IMG="<img src=\"${PI_CAMERA_URL}/snapshot\" style=\"width:100%;border-radius:6px;\">"
                            echo "$CAM_IMG" > "$THINKING_FILE"
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] $CAM_IMG"
                            echo "" > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt
                            ;;
                        *open\ it*|*open\ that*|*open\ this*)
                            LAST_URL=$(cat /tmp/jarvis_last_opened 2>/dev/null)
                            if [ -n "$LAST_URL" ]; then
                                xdg-open "$LAST_URL" 2>/dev/null &
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Opened."
                                echo "Opened." > "$RESPONSE"
                            else
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Open what? Tell me a site like YouTube or Google."
                                echo "Open what? Tell me a site like YouTube or Google." > "$RESPONSE"
                            fi
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *reboot*|*shutdown*)
                            echo "Commanding Pi..." > "$THINKING_FILE"
                            if [[ "$LOWERCASE" == *reboot* ]]; then
                                $PI_SSH "sudo reboot" 2>/dev/null &
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Pi rebooting"
                                echo "Pi rebooting" > "$RESPONSE"
                            else
                                $PI_SSH "sudo shutdown -h now" 2>/dev/null &
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Pi shutting down"
                                echo "Pi shutting down" > "$RESPONSE"
                            fi
                            echo "0" > /tmp/jarvis_status.txt
                            ;;
                        *youtube*)
                            xdg-open "https://youtube.com" 2>/dev/null &
                            echo "https://youtube.com" > /tmp/jarvis_last_opened
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] YouTube opened in your default browser."
                            echo "YouTube opened in your default browser." > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *time*|*clock*)
                            NOW=$(date '+%I:%M %p')
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] The time is $NOW"
                            echo "The time is $NOW" > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *google*)
                            xdg-open "https://google.com" 2>/dev/null &
                            echo "https://google.com" > /tmp/jarvis_last_opened
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] Google opened in your default browser."
                            echo "Google opened in your default browser." > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *github*)
                            xdg-open "https://github.com" 2>/dev/null &
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] GitHub opened in your default browser."
                            echo "GitHub opened in your default browser." > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *reddit*)
                            xdg-open "https://reddit.com" 2>/dev/null &
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] Reddit opened in your default browser."
                            echo "Reddit opened in your default browser." > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *bollywood*)
                            xdg-open "https://youtube.com/results?search_query=bollywood+songs" 2>/dev/null &
                            write_response "$PROCESS_CHAT_ID" "[Jarvis] Playing Bollywood songs"
                            echo "Playing Bollywood songs" > "$RESPONSE"
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *search*|*look\ up*)
                            QUERY=$(echo "$TEXT" | sed 's/^\[.*\] //' | sed 's/.*search //i; s/.*look up //i')
                            if [ -n "$QUERY" ]; then
                                ENCODED=$(echo "$QUERY" | sed 's/ /+/g')
                                xdg-open "https://google.com/search?q=$ENCODED" 2>/dev/null &
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] Searching for $QUERY"
                                echo "Searching for $QUERY" > "$RESPONSE"
                            else
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] What should I search for?"
                                echo "What should I search for?" > "$RESPONSE"
                            fi
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *spell*)
                            WORD=$(echo "$TEXT" | sed 's/^\[.*\] //' | sed 's/.*spell //i')
                            if [ -n "$WORD" ]; then
                                SPELLED=$(echo "$WORD" | sed 's/./& /g' | tr 'a-z' 'A-Z')
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] $WORD is spelled: $SPELLED"
                                echo "$WORD is spelled: $SPELLED" > "$RESPONSE"
                            else
                                write_response "$PROCESS_CHAT_ID" "[Jarvis] What word should I spell?"
                                echo "What word should I spell?" > "$RESPONSE"
                            fi
                            echo "0" > /tmp/jarvis_status.txt ;;
                        *)
                            echo "1" > /tmp/jarvis_status.txt
                            echo "Processing..." > "$THINKING_FILE"
                            ESCAPED=$(printf '%s' "$TEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')
                            OUTPUT=$(cd "$JARVIS_DIR" && source venv/bin/activate && python3 ask.py "$ESCAPED" --source "$SOURCE" --chat-id "$PROCESS_CHAT_ID" 2>/tmp/jarvis_ask_error.log)
                            if [ -z "$OUTPUT" ]; then
                                OUTPUT="I didn't catch that — could you try again?"
                            fi
                            case "$OUTPUT" in
                                __STOP_TTS__)
                                    pkill -f "edge-tts\|gtts-cli\|tts" 2>/dev/null
                                    echo "0" > /tmp/jarvis_status.txt
                                    ;;
                                __SHOW_CAMERA__)
                        OUTPUT="<img src=\"${PI_CAMERA_URL}/video_feed\" style=\"width:100%;border-radius:6px;\" />"
                                    echo "$OUTPUT" > "$THINKING_FILE"
                                    write_response "$PROCESS_CHAT_ID" "[Jarvis] $OUTPUT"
                                    echo "" > "$RESPONSE"
                                    echo "0" > /tmp/jarvis_status.txt
                                    ;;
                                *)
                                    write_response "$PROCESS_CHAT_ID" "[Jarvis] $OUTPUT"
                                    echo "$OUTPUT" > "$RESPONSE"
                                    echo "0" > /tmp/jarvis_status.txt
                                    ;;
                            esac
                            : > "$THINKING_FILE"
                            ;;
                    esac ;;
            esac
            LAST_LINE="$CURRENT"
        done <<< "$PENDING_LINES"
    fi
    sleep 1
done
