#!/bin/bash
# Fix ALC1220 analog mic - just sets hardware registers, no service restarts
sudo hda-verb /dev/snd/hwC1D0 0x14 SET_EAPD_BTLENABLE 0x0002
sudo hda-verb /dev/snd/hwC1D0 0x14 SET_amp 0xb080
echo "Mic pin reset done. Test with: arecord -d 3 -f S16_LE -r 16000 -c 1 /tmp/test.wav && aplay /tmp/test.wav"
