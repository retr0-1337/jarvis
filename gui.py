import tkinter as tk
from tkinter import scrolledtext
import os
import re
from datetime import datetime

from config import TRANSCRIPT_FILE, RESPONSE_FILE, CONV_LOG

TRANSCRIPT_FILE = str(TRANSCRIPT_FILE)
RESPONSE_FILE = str(RESPONSE_FILE)
LOG_FILE = str(CONV_LOG)

class JarvisGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Jarvis")
        self.root.geometry("700x500")
        self.root.configure(bg="#1e1e1e")

        self.text_area = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, bg="#1e1e1e", fg="#d4d4d4",
            font=("Cascadia Code", 11), insertbackground="white",
            relief=tk.FLAT, padx=10, pady=10, borderwidth=0
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.text_area.config(state=tk.DISABLED)

        self.text_area.tag_config("user", foreground="#569cd6", font=("Cascadia Code", 11, "bold"))
        self.text_area.tag_config("jarvis", foreground="#4ec9b0", font=("Cascadia Code", 11, "bold"))
        self.text_area.tag_config("timestamp", foreground="#6a9955", font=("Cascadia Code", 9))
        self.text_area.tag_config("system", foreground="#c586c0", font=("Cascadia Code", 11, "bold"))

        self.transcript_pos = 0
        self.last_response_mtime = 0
        self.last_displayed_response = ""

        self.add_message("System", "Jarvis started", "system")
        self.build_from_log()
        self.poll()

    def build_from_log(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if line.startswith("[You] "):
                        self.text_area.config(state=tk.NORMAL)
                        self.text_area.insert(tk.END, f"You: ", "user")
                        self.text_area.insert(tk.END, f"{line[6:]}\n")
                        self.text_area.see(tk.END)
                        self.text_area.config(state=tk.DISABLED)
                    elif line.startswith("[Jarvis] "):
                        self.text_area.config(state=tk.NORMAL)
                        self.text_area.insert(tk.END, f"Jarvis: ", "jarvis")
                        self.text_area.insert(tk.END, f"{line[9:]}\n")
                        self.text_area.see(tk.END)
                        self.text_area.config(state=tk.DISABLED)

    def add_message(self, sender, message, tag=None):
        if not message:
            return
        now = datetime.now().strftime("%H:%M:%S")
        tag = sender.lower() if not tag else tag
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"[{now}] ", "timestamp")
        label = "You: " if sender == "You" else "Jarvis: "
        self.text_area.insert(tk.END, label, tag)
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)

        with open(LOG_FILE, "a") as f:
            f.write(f"[{sender}] {message}\n")

    def poll(self):
        if os.path.exists(TRANSCRIPT_FILE):
            with open(TRANSCRIPT_FILE, "r") as f:
                f.seek(self.transcript_pos)
                new_data = f.read()
                if new_data:
                    for line in new_data.strip().split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        text = re.sub(r"^\[.*?\]\s*", "", line)
                        if text:
                            self.add_message("You", text)
                    self.transcript_pos = f.tell()

        if os.path.exists(RESPONSE_FILE):
            try:
                mtime = os.path.getmtime(RESPONSE_FILE)
                if mtime > self.last_response_mtime:
                    with open(RESPONSE_FILE, "r") as f:
                        content = f.read().strip()
                    if content and content != self.last_displayed_response:
                        self.last_displayed_response = content
                        self.last_response_mtime = mtime
                        self.add_message("Jarvis", content)
            except (FileNotFoundError, OSError):
                pass

        self.root.after(100, self.poll)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    JarvisGUI().run()
