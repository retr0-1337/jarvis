
echo "wow" 
sleep 1
python -m venv venv
sleep 1
source venv/bin/activate
sleep 1
pip install SpeechRecognition pyaudio edge-tts requests
#sleep 1
#ollama run mistral &
sleep 1
python3 jarv2.py
