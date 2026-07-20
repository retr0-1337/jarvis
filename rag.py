import json
import os
import sys
import subprocess

from config import DATA_DIR, CHATS_DIR, CONV_LOG

STORE_FILE = str(DATA_DIR / "rag_store.json")
CHAT_DIR = str(CHATS_DIR)
CONV_LOG = str(CONV_LOG)


def embed(text):
    result = subprocess.run(
        ["ollama", "run", "nomic-embed-text"],
        input=text, capture_output=True, text=True, timeout=30
    )
    return [float(x) for x in result.stdout.strip().split("\n")[-1].strip("[]").split(",")]


def load_store():
    if os.path.exists(STORE_FILE):
        try:
            with open(STORE_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            # Corrupted store — reset and rebuild
            print(f"[RAG] Corrupted store file, resetting", file=sys.stderr)
            return {"chunks": [], "embeddings": []}
    return {"chunks": [], "embeddings": []}


def save_store(store):
    os.makedirs(os.path.dirname(STORE_FILE), exist_ok=True)
    with open(STORE_FILE, "w") as f:
        json.dump(store, f)


def chunk_conversation(text, role, chat_id="", timestamp=""):
    chunks = []
    current = ""

    def flush():
        nonlocal current
        if current.strip():
            chunks.append({"text": f"[{role}] {current.strip()}", "chat": chat_id, "ts": timestamp})
        current = ""

    in_code_block = False
    lines = text.strip().split("\n")
    for line in lines:
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            current += line + "\n"
            if not in_code_block:
                flush()
            continue
        if in_code_block:
            current += line + "\n"
            continue
        if len(current) + len(line) > 500:
            flush()
            current = line + "\n"
        else:
            current += line + "\n"
    flush()
    return chunks


def index_file(filepath):
    store = load_store()
    existing_texts = {c["text"] for c in store["chunks"]}
    count = 0
    chat_id = os.path.splitext(os.path.basename(filepath))[0]
    if chat_id == "conversation":
        chat_id = "legacy"

    messages = []
    current_msg = None

    with open(filepath) as f:
        for line in f:
            line = line.rstrip("\n")
            is_new_msg = False
            role = "You"
            text = line
            ts = ""
            if "] [You] " in line:
                parts = line.split("] [You] ", 1)
                ts = parts[0].lstrip("[")
                text = parts[1]
                role = "You"
                is_new_msg = True
            elif "] [Jarvis] " in line:
                parts = line.split("] [Jarvis] ", 1)
                ts = parts[0].lstrip("[")
                text = parts[1]
                role = "Jarvis"
                is_new_msg = True
            elif line.startswith("[") and "] " in line:
                parts = line.split("] ", 1)
                ts = parts[0].lstrip("[")
                text = parts[1]
                is_new_msg = True

            if is_new_msg:
                if current_msg:
                    messages.append(current_msg)
                current_msg = {"role": role, "text": text, "ts": ts, "chat": chat_id}
            elif current_msg:
                current_msg["text"] += "\n" + text

        if current_msg:
            messages.append(current_msg)

    for msg in messages:
        if not msg["text"] or len(msg["text"].split()) < 2:
            continue
        chunks = chunk_conversation(msg["text"], msg["role"], msg["chat"], msg["ts"])
        for chunk in chunks:
            if chunk["text"] not in existing_texts:
                try:
                    emb = embed(chunk["text"])
                    store["chunks"].append(chunk)
                    store["embeddings"].append(emb)
                    existing_texts.add(chunk["text"])
                    count += 1
                except:
                    pass

    save_store(store)
    return count


def index_all():
    total = 0
    if os.path.exists(CONV_LOG):
        total += index_file(CONV_LOG)
    if os.path.exists(CHAT_DIR):
        for fname in os.listdir(CHAT_DIR):
            if fname.endswith(".log"):
                total += index_file(os.path.join(CHAT_DIR, fname))
    return total


def cosine_sim(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x ** 2 for x in a) ** 0.5
    mag_b = sum(x ** 2 for x in b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0
    return dot / (mag_a * mag_b)


def search(query, k=3):
    store = load_store()
    if not store["chunks"]:
        return ""

    try:
        q_emb = embed(query)
    except:
        return ""

    scored = []
    for i, emb in enumerate(store["embeddings"]):
        sim = cosine_sim(q_emb, emb)
        scored.append((sim, i))

    scored.sort(reverse=True)

    included = set()
    results = []

    def find_adjacent_jarvis(idx, chat, direction=1):
        """Find nearest [Jarvis] chunk from same chat, searching in given direction."""
        search_range = range(idx + direction, idx + (6 * direction), direction) if direction > 0 else range(idx - 1, max(idx - 6, -1), -1)
        for j in search_range:
            if j < 0 or j >= len(store["chunks"]):
                continue
            if j in included:
                continue
            nc = store["chunks"][j]
            if nc.get("chat") == chat and nc["text"].startswith("[Jarvis]"):
                return j
        return None

    for sim, i in scored:
        if len(results) >= k + 5:
            break
        if sim < 0.5:
            break
        if i in included:
            continue
        chunk = store["chunks"][i]
        if not chunk["text"].startswith("[Jarvis]"):
            chat = chunk.get("chat", "")
            # Look forward and backward for adjacent Jarvis chunk
            j = find_adjacent_jarvis(i, chat, direction=1)
            if j is None:
                j = find_adjacent_jarvis(i, chat, direction=-1)
            if j is not None:
                results.append(store["chunks"][j]["text"])
                included.add(j)
            continue
        results.append(chunk["text"])
        included.add(i)

    if not results:
        return ""

    junk_patterns = ["fake noodles", "impasta", "riddle", "joke"]
    filtered = []
    for r in results:
        lower = r.lower()
        if any(jp in lower for jp in junk_patterns):
            continue
        filtered.append(r)

    if not filtered:
        return ""

    return "Relevant past conversation:\n" + "\n---\n".join(filtered[:k])


def index_new_lines(filepath, max_new=30):
    """Index new lines from a chat file. max_new limits embedding calls per invocation."""
    store = load_store()
    existing_texts = {c["text"] for c in store["chunks"]}
    count = 0
    chat_id = os.path.splitext(os.path.basename(filepath))[0]
    if chat_id == "conversation":
        chat_id = "legacy"

    try:
        with open(filepath) as f:
            raw_lines = f.readlines()
    except:
        return 0

    messages = []
    current_msg = None

    for line in raw_lines:
        line = line.rstrip("\n")
        is_new_msg = False
        role = "You"
        text = line
        ts = ""
        if "] [You] " in line:
            parts = line.split("] [You] ", 1)
            ts = parts[0].lstrip("[")
            text = parts[1]
            role = "You"
            is_new_msg = True
        elif "] [Jarvis] " in line:
            parts = line.split("] [Jarvis] ", 1)
            ts = parts[0].lstrip("[")
            text = parts[1]
            role = "Jarvis"
            is_new_msg = True
        elif line.startswith("[") and "] " in line:
            parts = line.split("] ", 1)
            ts = parts[0].lstrip("[")
            text = parts[1]
            is_new_msg = True

        if is_new_msg:
            if current_msg:
                messages.append(current_msg)
            current_msg = {"role": role, "text": text, "ts": ts, "chat": chat_id}
        elif current_msg:
            current_msg["text"] += "\n" + text

    if current_msg:
        messages.append(current_msg)

    # Process most recent messages first, cap embedding calls
    for msg in reversed(messages):
        if count >= max_new:
            break
        if not msg["text"] or len(msg["text"].split()) < 2:
            continue
        chunks = chunk_conversation(msg["text"], msg["role"], msg["chat"], msg["ts"])
        for chunk in chunks:
            if count >= max_new:
                break
            if chunk["text"] not in existing_texts:
                try:
                    emb = embed(chunk["text"])
                    store["chunks"].append(chunk)
                    store["embeddings"].append(emb)
                    existing_texts.add(chunk["text"])
                    count += 1
                except:
                    pass

    if count > 0:
        save_store(store)
    return count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: rag.py <index|search|index-new> [query]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "index":
        n = index_all()
        print(f"Indexed {n} new chunks")
    elif cmd == "index-new":
        if len(sys.argv) < 3:
            print("Usage: rag.py index-new <filepath>")
            sys.exit(1)
        n = index_new_lines(sys.argv[2])
        print(f"Indexed {n} new chunks")
    elif cmd == "search":
        if len(sys.argv) < 3:
            print("Usage: rag.py search <query>")
            sys.exit(1)
        query = " ".join(sys.argv[2:])
        result = search(query)
        print(result)
