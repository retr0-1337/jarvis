"""
jarvis_memory.py — 3-tier per-chat memory system.

Each chat has its own memory file: {chat_id}.memory.json
- SHORT-TERM: last 20 message pairs (current session)
- MID-TERM: daily summaries (last 30 days)
- LONG-TERM: user preferences, key facts, topic counts
"""

import json
import os
import sys
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

CHAT_DIR = os.path.expanduser("~/.local/share/jarvis/chats")

SHORT_TERM_MAX = 20      # message pairs
MID_TERM_MAX_DAYS = 30    # daily summaries
MID_TERM_MAX_SUMMARIES = 30
LONG_TERM_MAX_FACTS = 50  # max key facts to retain


def _memory_path(chat_id: str) -> str:
    return os.path.join(CHAT_DIR, f"{chat_id}.memory.json")


def _chat_log_path(chat_id: str) -> str:
    return os.path.join(CHAT_DIR, f"{chat_id}.log")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def load(chat_id: str) -> dict:
    path = _memory_path(chat_id)
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
            # Ensure all tiers exist
            data.setdefault("short_term", [])
            data.setdefault("mid_term", {})
            data.setdefault("long_term", {
                "user_preferences": {},
                "key_facts": [],
                "topics": {}
            })
            return data
        except (json.JSONDecodeError, ValueError):
            pass
    return {
        "chat_id": chat_id,
        "created_at": _now(),
        "short_term": [],
        "mid_term": {},
        "long_term": {
            "user_preferences": {},
            "key_facts": [],
            "topics": {}
        }
    }


def save(chat_id: str, memory: dict):
    os.makedirs(CHAT_DIR, exist_ok=True)
    path = _memory_path(chat_id)
    with open(path, "w") as f:
        json.dump(memory, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════
# SHORT-TERM MEMORY
# ═══════════════════════════════════════════════════════════════════════

def add_short_term(chat_id: str, role: str, text: str):
    """Add a message to short-term memory. Called after every user/assistant turn."""
    memory = load(chat_id)
    memory["short_term"].append({
        "role": role,
        "text": text[:500],  # truncate long messages
        "ts": _now()
    })
    # Keep only last SHORT_TERM_MAX * 2 entries (user + assistant pairs)
    if len(memory["short_term"]) > SHORT_TERM_MAX * 2:
        memory["short_term"] = memory["short_term"][-SHORT_TERM_MAX * 2:]
    save(chat_id, memory)


def get_short_term(chat_id: str, n: int = None) -> str:
    """Get short-term memory as formatted context string for the LLM."""
    memory = load(chat_id)
    msgs = memory["short_term"]
    if n:
        msgs = msgs[-n:]
    if not msgs:
        return ""
    lines = []
    for m in msgs:
        label = "You" if m["role"] == "user" else "Jarvis"
        lines.append(f"[{label}]: {m['text'][:300]}")
    return "\n".join(lines)


def get_short_term_raw(chat_id: str) -> list:
    """Get short-term memory as raw list of dicts."""
    return load(chat_id)["short_term"]


# ═══════════════════════════════════════════════════════════════════════
# MID-TERM MEMORY
# ═══════════════════════════════════════════════════════════════════════

def generate_mid_term_summary(chat_id: str) -> str:
    """Generate a daily summary of the chat using LLM. Called on chat switch/close."""
    log_path = _chat_log_path(chat_id)
    if not os.path.exists(log_path):
        return ""

    # Read today's messages
    today = _today()
    today_msgs = []
    try:
        with open(log_path) as f:
            for line in f:
                if line.startswith("[") and today in line:
                    today_msgs.append(line.strip())
    except Exception:
        return ""

    if not today_msgs:
        return ""

    conversation = "\n".join(today_msgs[-50:])  # last 50 lines

    prompt = f"""Summarize this conversation in 3-5 bullet points.
Focus on: topics discussed, decisions made, code written, key facts learned.
Be concise. Use plain text, not markdown.

Conversation:
{conversation}

Summary:"""

    try:
        model = __import__("config").get("ollama_model")
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()[:1000]
    except Exception:
        return ""


def add_mid_term(chat_id: str, summary: str = None):
    """Add or update today's mid-term summary."""
    memory = load(chat_id)
    today = _today()

    if summary is None:
        summary = generate_mid_term_summary(chat_id)

    if summary:
        memory["mid_term"][today] = {
            "summary": summary,
            "updated_at": _now()
        }

    # Prune old entries
    dates = sorted(memory["mid_term"].keys())
    while len(dates) > MID_TERM_MAX_SUMMARIES:
        oldest = dates.pop(0)
        del memory["mid_term"][oldest]

    save(chat_id, memory)


def get_mid_term(chat_id: str, days: int = 7) -> str:
    """Get mid-term memory as formatted context string."""
    memory = load(chat_id)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    summaries = []
    for date in sorted(memory["mid_term"].keys(), reverse=True):
        if date < cutoff:
            break
        entry = memory["mid_term"][date]
        summaries.append(f"[{date}] {entry['summary']}")
    if not summaries:
        return ""
    return "Recent conversation summaries:\n" + "\n".join(summaries)


# ═══════════════════════════════════════════════════════════════════════
# LONG-TERM MEMORY
# ═══════════════════════════════════════════════════════════════════════

def extract_long_term_facts(chat_id: str, user_msg: str, jarvis_msg: str) -> dict:
    """Extract user preferences and key facts from a conversation turn using LLM."""
    prompt = f"""Extract key information from this conversation. Return ONLY valid JSON.

Rules:
- user_preferences: dict of key:value pairs about the user (language, style, projects)
- key_facts: list of strings, each a single fact learned about the user or their work
- topics: dict of topic_name -> count (how many times discussed)

Only extract NEW information not already in existing_facts. Be selective.
If nothing notable, return {{"user_preferences": {{}}, "key_facts": [], "topics": {{}}}}

User: {user_msg[:300]}
Jarvis: {jarvis_msg[:300]}"""

    try:
        model = __import__("config").get("ollama_model")
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt, capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        # Extract JSON from response
        start = output.find("{")
        end = output.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(output[start:end])
    except Exception:
        pass
    return {"user_preferences": {}, "key_facts": [], "topics": {}}


def update_long_term(chat_id: str, user_msg: str, jarvis_msg: str):
    """Update long-term memory after a conversation turn."""
    memory = load(chat_id)
    lt = memory["long_term"]

    # Extract new facts
    extracted = extract_long_term_facts(chat_id, user_msg, jarvis_msg)

    # Merge preferences
    for k, v in extracted.get("user_preferences", {}).items():
        if v:
            lt["user_preferences"][k] = v

    # Merge key facts (deduplicate)
    existing = set(lt.get("key_facts", []))
    for fact in extracted.get("key_facts", []):
        if fact and fact not in existing:
            lt["key_facts"].append(fact)
            existing.add(fact)

    # Prune if too many
    if len(lt["key_facts"]) > LONG_TERM_MAX_FACTS:
        lt["key_facts"] = lt["key_facts"][-LONG_TERM_MAX_FACTS:]

    # Update topic counts
    for topic, count in extracted.get("topics", {}).items():
        if topic:
            if topic in lt["topics"]:
                lt["topics"][topic]["count"] = lt["topics"][topic].get("count", 0) + count
                lt["topics"][topic]["last_used"] = _now()
            else:
                lt["topics"][topic] = {"count": count, "last_used": _now()}

    memory["long_term"] = lt
    save(chat_id, memory)


def get_long_term(chat_id: str) -> str:
    """Get long-term memory as formatted context string."""
    memory = load(chat_id)
    lt = memory["long_term"]
    parts = []

    # User preferences
    prefs = lt.get("user_preferences", {})
    if prefs:
        prefs_str = ", ".join(f"{k}: {v}" for k, v in prefs.items())
        parts.append(f"User preferences: {prefs_str}")

    # Key facts
    facts = lt.get("key_facts", [])
    if facts:
        parts.append("Key facts:\n" + "\n".join(f"  - {f}" for f in facts[-15:]))

    # Top topics
    topics = lt.get("topics", {})
    if topics:
        sorted_topics = sorted(topics.items(), key=lambda x: x[1].get("count", 0), reverse=True)[:5]
        topic_str = ", ".join(f"{t} ({d.get('count', 0)}x)" for t, d in sorted_topics)
        parts.append(f"Frequent topics: {topic_str}")

    if not parts:
        return ""
    return "Long-term memory:\n" + "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# COMBINED CONTEXT (for LLM prompts)
# ═══════════════════════════════════════════════════════════════════════

def get_full_context(chat_id: str, max_short: int = 10) -> str:
    """Get all three tiers combined as a context block for the LLM."""
    if not chat_id:
        return ""

    parts = []

    short = get_short_term(chat_id, n=max_short)
    if short:
        parts.append("=== CURRENT CONVERSATION ===\n" + short)

    mid = get_mid_term(chat_id, days=7)
    if mid:
        parts.append(mid)

    long = get_long_term(chat_id)
    if long:
        parts.append(long)

    if not parts:
        return ""

    return "\n\n".join(parts) + "\n\n"


def get_context_for_intent(chat_id: str) -> dict:
    """Get memory context specifically for the intent classifier."""
    if not chat_id:
        return {}
    memory = load(chat_id)
    return {
        "last_code": memory["short_term"][-1]["text"] if memory["short_term"] and memory["short_term"][-1]["role"] == "assistant" else "",
        "recent_topics": list(memory["long_term"].get("topics", {}).keys())[:5],
        "user_preferences": memory["long_term"].get("user_preferences", {}),
    }


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: jarvis_memory.py <chat_id> <show|update-mid|update-long>")
        sys.exit(1)

    chat_id = sys.argv[1]
    cmd = sys.argv[2]

    if cmd == "show":
        m = load(chat_id)
        print(json.dumps(m, indent=2, ensure_ascii=False))
    elif cmd == "update-mid":
        add_mid_term(chat_id)
        print("Mid-term updated")
    elif cmd == "update-long":
        if len(sys.argv) < 5:
            print("Usage: jarvis_memory.py <chat_id> update-long <user_msg> <jarvis_msg>")
            sys.exit(1)
        update_long_term(chat_id, sys.argv[3], sys.argv[4])
        print("Long-term updated")
    else:
        print(f"Unknown command: {cmd}")
