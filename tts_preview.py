import sys
import edge_tts
import asyncio

text = sys.argv[1]
voice = sys.argv[2]
out = sys.argv[3]

async def gen():
    comm = edge_tts.Communicate(text, voice)
    await comm.save(out)

asyncio.run(gen())
