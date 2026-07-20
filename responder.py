import os
import time
import asyncio
import subprocess
import tempfile
import edge_tts

from config import TRANSCRIPT_FILE, RESPONSE_FILE

TTS_VOICE = "en-US-SteffanNeural"
TRANSCRIPT_FILE = str(TRANSCRIPT_FILE)
RESPONSE_FILE = str(RESPONSE_FILE)

async def speak(text):
    try:
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
            tts = edge_tts.Communicate(text, TTS_VOICE)
            await tts.save(f.name)
        subprocess.run(["paplay", f.name], check=True)
    except Exception as e:
        print(f"[TTS Error: {e}]")

last_line = ""
while True:
    try:
        if not os.path.exists(TRANSCRIPT_FILE):
            time.sleep(0.3)
            continue
        with open(TRANSCRIPT_FILE, "r") as f:
            lines = f.read().strip().split("\n")
        if lines and lines[-1] != last_line:
            last_line = lines[-1]
            # Extract text after timestamp
            text = last_line.split("] ", 1)[-1] if "] " in last_line else last_line
            text = text.strip()
            if text:
                print(f"[Responder] Heard: {text}")
                asyncio.run(speak(text))
        time.sleep(0.3)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"[Responder Error: {e}]")
        time.sleep(1)
