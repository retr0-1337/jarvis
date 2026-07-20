import speech_recognition as sr
import threading
import subprocess
import tempfile
import os
import wave
import time
import struct
import numpy as np
from datetime import datetime
import signal

import config
from config import PROJECT_DIR, TRANSCRIPT_FILE, RESPONSE_FILE, CONV_LOG, CUDA_LIB

if CUDA_LIB:
    os.environ["LD_LIBRARY_PATH"] = CUDA_LIB

_cfg = config.load_config()

TTS_VOICE = _cfg.get("tts_voice", "en-US-SteffanNeural")
CONFIG_FILE = str(config.CONFIG_FILE)
_config_mtime = os.path.getmtime(CONFIG_FILE) if os.path.exists(CONFIG_FILE) else 0
TRANSCRIPT_FILE = str(TRANSCRIPT_FILE)
RESPONSE_FILE = str(RESPONSE_FILE)
CONV_LOG = str(CONV_LOG)
MIC_MUTED_FILE = "/tmp/jarvis_mic_muted"

def _handle_stop_tts(signum, frame):
    """SIGUSR1 handler — stop TTS playback from webui signal."""
    stop_tts()
    try:
        open(RESPONSE_FILE, "w").close()
    except:
        pass
    log("TTS stopped via SIGUSR1")

signal.signal(signal.SIGUSR1, _handle_stop_tts)

from faster_whisper import WhisperModel
whisper = WhisperModel(_cfg.get("whisper_model", "base.en"), device="cuda", compute_type="float16")
import edge_tts
import asyncio
import webrtcvad

vad = webrtcvad.Vad(_cfg.get("vad_aggressiveness", 3))

last_spoke_at = 0.0
tts_process = None
tts_lock = threading.Lock()

def stop_tts():
    global tts_process
    with tts_lock:
        if tts_process and tts_process.poll() is None:
            try:
                tts_process.kill()
            except:
                pass
        tts_process = None

def speak_sync(text):
    global last_spoke_at, tts_process
    try:
        fifo_path = "/tmp/jarvis_tts_fifo"
        if os.path.exists(fifo_path):
            os.remove(fifo_path)
        os.mkfifo(fifo_path)
        proc = subprocess.Popen(["paplay", "--latency-msec=50", fifo_path])
        with tts_lock:
            tts_process = proc
        speed = _cfg.get("tts_speed", 1.0)
        rate = f"+{int((speed - 1) * 100)}%" if speed >= 1.0 else f"{int((speed - 1) * 100)}%"
        async def _stream_tts():
            communicate = edge_tts.Communicate(text, TTS_VOICE, rate=rate)
            try:
                with open(fifo_path, "wb") as fifo:
                    async for chunk in communicate.stream():
                        if chunk["type"] == "audio":
                            try:
                                fifo.write(chunk["data"])
                                fifo.flush()
                            except BrokenPipeError:
                                break
            except:
                pass
        asyncio.run(_stream_tts())
        proc.wait()
        with tts_lock:
            if tts_process == proc:
                tts_process = None
        try:
            os.remove(fifo_path)
        except:
            pass
    except:
        pass
    last_spoke_at = time.time()

def response_watcher():
    global last_spoke_at
    last_mtime = 0
    while True:
        try:
            if not os.path.exists(RESPONSE_FILE):
                time.sleep(0.3)
                continue
            mtime = os.path.getmtime(RESPONSE_FILE)
            if mtime > last_mtime:
                with open(RESPONSE_FILE, "r") as f:
                    content = f.read().strip()
                if content:
                    last_mtime = mtime
                    import re
                    spoken = re.sub(r'```[\s\S]*?```', '', content).strip()
                    spoken = re.sub(r'<!--[\s\S]*?-->', '', spoken)
                    spoken = re.sub(r'<(img|video)[^>]*>(?:</\1>)?', '', spoken).strip()
                    spoken = re.sub(r'\*\*\*(.+?)\*\*\*', r'\1', spoken)
                    spoken = re.sub(r'\*\*(.+?)\*\*', r'\1', spoken)
                    spoken = re.sub(r'\*(.+?)\*', r'\1', spoken)
                    spoken = re.sub(r'__([^_]+)__', r'\1', spoken)
                    spoken = re.sub(r'_([^_]+)_', r'\1', spoken)
                    spoken = re.sub(r'~~(.+?)~~', r'\1', spoken)
                    spoken = spoken.replace('#', '').strip()
                    if spoken:
                        if not os.path.exists("/tmp/jarvis_tts_muted"):
                            print(f"-> {spoken}", flush=True)
                            speak_sync(spoken)
                    open(RESPONSE_FILE, "w").close()
            time.sleep(0.3)
        except:
            time.sleep(1)

def has_speech(pcm, rate=16000):
    frame_len = 480
    frames = [pcm[i:i+frame_len*2] for i in range(0, len(pcm), frame_len*2)]
    frames = [f for f in frames if len(f) == frame_len * 2]
    if not frames:
        return False
    speech_count = sum(1 for f in frames if vad.is_speech(f, rate))
    return speech_count / len(frames) >= 0.3

def is_hallucination(text):
    words = text.lower().split()
    if len(words) < 2:
        return True
    if len(set(words)) == 1 and len(words) > 1:
        return True
    for w in set(words):
        if words.count(w) > len(words) * 0.5 and len(words) > 2:
            return True
    always_junk = ["thanks for watching", "subscribe", "sorry sorry", "hello hello",
                    "the the", "well well", "so so", "you you", "i'm sorry", "im sorry",
                    "music", "applause"]
    lower = text.lower()
    for j in always_junk:
        if j in lower:
            return True
    short_junk = ["thank you", "thanks", "thank", "bye", "hello", "please", "well"]
    if len(words) <= 4:
        if any(j in lower for j in short_junk):
            return True
    if len(text) > 60 and len(words) < 6:
        return True
    return False

_stop_recognizer = None
_mic_lock = threading.Lock()
_tts_bg_rms = 0.0
_tts_bg_peak = 0.0

def check_mic_for_stop(source=None):
    global _stop_recognizer, _tts_bg_rms, _tts_bg_peak
    try:
        if _stop_recognizer is None:
            _stop_recognizer = sr.Recognizer()
            _stop_recognizer.energy_threshold = _cfg.get("energy_threshold")
            _stop_recognizer.dynamic_energy_threshold = False
        if source is not None:
            audio = _stop_recognizer.record(source, duration=0.5)
        else:
            with sr.Microphone(device_index=_get_mic_index()) as src:
                audio = _stop_recognizer.record(src, duration=0.5)
        pcm = audio.get_raw_data(convert_rate=16000)
        del audio
        if len(pcm) < 800:
            return False
        samples = np.frombuffer(pcm, dtype=np.int16).astype(np.float32)
        rms = float(np.sqrt(np.mean(samples ** 2)))
        peak = float(np.max(np.abs(samples)))

        # If audio is similar to TTS baseline (just TTS leakage), skip
        # Only process if user voice is distinctly louder/different from TTS
        if _tts_bg_peak > 0:
            if peak < _tts_bg_peak * 3.0 and rms < _tts_bg_rms * 2.0:
                return False

        frame_len = 480
        frames = [pcm[i:i+frame_len*2] for i in range(0, len(pcm), frame_len*2)]
        frames = [f for f in frames if len(f) == frame_len * 2]
        if not frames:
            return False
        speech = sum(1 for f in frames if vad.is_speech(f, 16000))
        speech_ratio = speech / len(frames)
        if speech_ratio < 0.1:
            return False
        wav_path = tempfile.mktemp(suffix=".wav")
        try:
            import wave as _w
            with _w.open(wav_path, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(16000)
                wf.writeframes(pcm)
            segments, _ = whisper.transcribe(wav_path, language="en", no_speech_threshold=0.6)
            text = " ".join(s.text.strip() for s in segments if s.no_speech_prob < 0.5).strip().lower()
            del segments
        finally:
            try:
                os.unlink(wav_path)
            except:
                pass
        import re as _re
        clean = _re.sub(r'[^\w\s]', '', text).strip().lower()
        log(f"stop: '{clean}' rms={rms:.0f} peak={peak:.0f} bg={_tts_bg_rms:.0f}")
        stop_words = ["stop", "shut", "quiet", "quiete", "mute", "enough", "cease"]
        stop_phrases = ["leave it", "that is enough", "thats enough", "shut up", "shut it"]
        if any(w in stop_words for w in clean.split()):
            log("stop: DETECTED (word)")
            return True
        if any(p in clean for p in stop_phrases):
            log("stop: DETECTED (phrase)")
            return True
        return False
    except:
        return False

def calibrate_tts_bg(source, duration=0.3):
    global _stop_recognizer, _tts_bg_rms, _tts_bg_peak
    try:
        if _stop_recognizer is None:
            _stop_recognizer = sr.Recognizer()
            _stop_recognizer.energy_threshold = _cfg.get("energy_threshold")
            _stop_recognizer.dynamic_energy_threshold = False
        audio = _stop_recognizer.record(source, duration=duration)
        pcm = audio.get_raw_data(convert_rate=16000)
        del audio
        samples = np.frombuffer(pcm, dtype=np.int16).astype(np.float32)
        _tts_bg_rms = float(np.sqrt(np.mean(samples ** 2)))
        _tts_bg_peak = float(np.max(np.abs(samples)))
        log(f"calibrated: rms={_tts_bg_rms:.0f} peak={_tts_bg_peak:.0f}")
    except:
        _tts_bg_rms = 500.0
        _tts_bg_peak = 3000.0

def tts_monitor():
    global tts_process
    while True:
        time.sleep(0.5)
        with tts_lock:
            speaking = tts_process is not None and tts_process.poll() is None
        if not speaking:
            continue
        try:
            with _mic_lock:
                with sr.Microphone(device_index=_get_mic_index()) as source:
                    calibrate_tts_bg(source, duration=0.3)
                    while True:
                        with tts_lock:
                            speaking = tts_process is not None and tts_process.poll() is None
                        if not speaking:
                            break
                        if check_mic_for_stop(source):
                            stop_tts()
                            open(RESPONSE_FILE, "w").close()
                            time.sleep(0.3)
                            break
        except Exception:
            pass

def _get_mic_index():
    """Resolve mic device name from config to integer index."""
    dev = _cfg.get("mic_device", "pipewire")
    try:
        return int(dev)
    except (ValueError, TypeError):
        names = sr.Microphone.list_microphone_names()
        for i, n in enumerate(names):
            if n == dev:
                return i
        # Fallback: prefer virtual devices that work with PipeWire
        for pref in ["pipewire", "default"]:
            for i, n in enumerate(names):
                if n == pref:
                    return i
        return None

LOG_FILE = "/tmp/jarv2.log"

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except:
        pass

def main():
    global last_spoke_at, _config_mtime, TTS_VOICE
    threading.Thread(target=response_watcher, daemon=True).start()
    threading.Thread(target=tts_monitor, daemon=True).start()
    recognizer = sr.Recognizer()
    recognizer.energy_threshold = _cfg.get("energy_threshold")
    recognizer.pause_threshold = 5.0
    recognizer.dynamic_energy_threshold = False
    mic_idx = _get_mic_index()
    log(f"mic_idx={mic_idx}")

    while True:
        try:
            if os.path.exists(MIC_MUTED_FILE):
                time.sleep(1)
                continue

            try:
                mtime = os.path.getmtime(CONFIG_FILE)
                if mtime > _config_mtime:
                    _config_mtime = mtime
                    fresh_cfg = config.load_config()
                    new_voice = fresh_cfg.get("tts_voice", "en-US-SteffanNeural")
                    if new_voice != TTS_VOICE:
                        log(f"Voice changed: {TTS_VOICE} -> {new_voice}")
                        TTS_VOICE = new_voice
                    if fresh_cfg.get("energy_threshold") != _cfg.get("energy_threshold"):
                        _cfg["energy_threshold"] = fresh_cfg["energy_threshold"]
                    new_speed = fresh_cfg.get("tts_speed", 1.0)
                    if new_speed != _cfg.get("tts_speed", 1.0):
                        log(f"Speed changed: {_cfg.get('tts_speed',1.0)} -> {new_speed}")
                        _cfg["tts_speed"] = new_speed
            except Exception:
                pass

            with tts_lock:
                tts_active = tts_process is not None and tts_process.poll() is None
            if tts_active:
                time.sleep(0.5)
                continue

            try:
                with _mic_lock:
                    with tts_lock:
                        tts_active = tts_process is not None and tts_process.poll() is None
                    if tts_active:
                        continue
                    with sr.Microphone(device_index=mic_idx) as source:
                        audio = recognizer.listen(source, timeout=10, phrase_time_limit=5)
            except sr.WaitTimeoutError:
                continue
            except Exception as e:
                log(f"Mic error: {type(e).__name__}: {e}")
                time.sleep(1)
                continue

            wav_data = audio.get_wav_data()
            pcm = audio.get_raw_data(convert_rate=16000)
            del audio

            if len(pcm) < 16000 * 0.3 * 2:
                del pcm, wav_data
                continue

            if not has_speech(pcm):
                del pcm, wav_data
                continue

            last_spoke_at = time.time()

            try:
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                    f.write(wav_data)
                    wav_path = f.name
                del wav_data
                try:
                    segments, info = whisper.transcribe(wav_path, no_speech_threshold=_cfg.get("no_speech_threshold"), log_prob_threshold=-1.2)
                    text = " ".join(s.text.strip() for s in segments if (s.end - s.start) >= _cfg.get("min_segment_duration") and s.no_speech_prob < 0.5).strip()
                    del segments, info
                finally:
                    os.unlink(wav_path)
            except:
                continue

            if not text:
                continue

            if is_hallucination(text):
                continue

            if len(text.split()) < 2:
                continue

            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {text}", flush=True)
            with open(TRANSCRIPT_FILE, "a") as f:
                f.write(f"[{timestamp}] [voice] {text}\n")
            with open(CONV_LOG, "a") as f:
                f.write(f"[{timestamp}] [You] {text}\n")
            active_chat_file = os.path.expanduser("~/.local/share/jarvis/active_chat")
            if os.path.exists(active_chat_file):
                chat_id = open(active_chat_file).read().strip()
                chat_log = os.path.expanduser(f"~/.local/share/jarvis/chats/{chat_id}.log")
                if chat_id and os.path.exists(chat_log):
                    with open(chat_log, "a") as f:
                        f.write(f"[{timestamp}] [You] {text}\n")

            if any(w in text.lower() for w in ["exit", "quit", "shutdown"]):
                break
        except Exception as e:
            log(f"Loop error: {type(e).__name__}: {e}")
            time.sleep(1)
            continue

if __name__ == "__main__":
    while True:
        try:
            log("jarv2 starting...")
            main()
            log("main() exited normally")
            break
        except KeyboardInterrupt:
            log("Interrupted")
            break
        except Exception as e:
            import traceback
            log(f"CRASHED: {type(e).__name__}: {e}")
            tb = traceback.format_exc()
            log(tb)
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(tb + "\n")
            except:
                pass
            log("Restarting in 3s...")
            time.sleep(3)
