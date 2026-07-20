import os
import sys
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import PROJECT_DIR, TRANSCRIPT_FILE, RESPONSE_FILE

TRANSCRIPT_FILE = str(TRANSCRIPT_FILE)
RESPONSE_FILE = str(RESPONSE_FILE)
PYTHON = sys.executable

def handle(text):
    t = text.lower().strip()

    if "restart" in t or "reload" in t:
        subprocess.Popen(["killall", "python"])
        time.sleep(1)
        subprocess.Popen([PYTHON, str(PROJECT_DIR / "jarv2.py")])
        subprocess.Popen([PYTHON, str(PROJECT_DIR / "auto.py")])
        return "Restarting!"

    if "shutdown" in t or "power off" in t or "turn off" in t:
        subprocess.Popen(["poweroff"])
        return "Shutting down"

    if "youtube" in t:
        subprocess.Popen(["xdg-open", "https://youtube.com"])
        return "Opening YouTube"

    if "google" in t and "youtube" not in t:
        subprocess.Popen(["xdg-open", "https://google.com"])
        return "Opening Google"

    if "github" in t:
        subprocess.Popen(["xdg-open", "https://github.com"])
        return "Opening GitHub"

    if "reddit" in t:
        subprocess.Popen(["xdg-open", "https://reddit.com"])
        return "Opening Reddit"

    if "time" in t or "clock" in t:
        return f"The time is {time.strftime('%I:%M %p')}"

    if "bollywood" in t:
        subprocess.Popen(["xdg-open", "https://youtube.com/results?search_query=bollywood+songs"])
        return "Playing Bollywood songs"

    if "pause" in t or "freeze" in t:
        subprocess.Popen(["playerctl", "pause"])
        return "Paused"

    if "continue" in t or "resume" in t or "unpause" in t:
        subprocess.Popen(["playerctl", "play"])
        return "Resumed"

    if "next" in t or "skip" in t:
        subprocess.Popen(["playerctl", "next"])
        return "Skipped"

    if "previous" in t or "back" in t:
        subprocess.Popen(["playerctl", "previous"])
        return "Going back"

    if "play" in t:
        query = t.replace("play", "").strip()
        if query and len(query) > 2:
            subprocess.Popen(["xdg-open", f"https://youtube.com/results?search_query={query}"])
            return f"Playing {query}"
        subprocess.Popen(["playerctl", "play"])
        return "Playing"

    if "spell" in t:
        word = t.replace("spell", "").strip()
        if word:
            spelled = " ".join(word.upper())
            return f"{word} is spelled: {spelled}"
        return "What word should I spell?"

    if "search" in t or "look up" in t:
        query = t.replace("search", "").replace("look up", "").strip()
        if query:
            subprocess.Popen(["xdg-open", f"https://google.com/search?q={query}"])
            return f"Searching for {query}"
        return "What should I search for?"

    return "Got it"

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
            text = last_line.split("] ", 1)[-1] if "] " in last_line else last_line
            text = text.strip()
            if text:
                resp = handle(text)
                if resp:
                    with open(RESPONSE_FILE, "w") as f:
                        f.write(resp)
        time.sleep(0.3)
    except KeyboardInterrupt:
        break
    except:
        time.sleep(1)
