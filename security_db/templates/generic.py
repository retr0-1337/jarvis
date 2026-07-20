"""Generic exploit template for Jarvis."""
from typing import Dict, Any


def render_generic(vuln: Dict[str, Any]) -> str:
    trigger = vuln.get("trigger_primitives", {})
    overflow_val = trigger.get("overflow_value") or "0x41414141"
    offset = trigger.get("offset") or "0x100"
    target = vuln.get("target", "target_binary")
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    description = vuln.get("description", "")
    vtype = vuln.get("vulnerability_type", "unknown")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".bin"

    c = '#!/usr/bin/env python3\n'
    c += '"""Generic exploit PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Vulnerability type: ' + vtype + '\n'
    c += 'Description: ' + description + '\n'
    c += '"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'def build_trigger(trigger_value=' + overflow_val + ', offset=' + offset + ') -> bytes:\n'
    c += '    """Build the trigger data."""\n'
    c += '    if isinstance(trigger_value, bytes):\n'
    c += '        return trigger_value\n'
    c += '    return bytes([0x41] * 256)\n\n\n'
    c += 'def main():\n'
    c += '    trigger = build_trigger()\n'
    c += '    output = "' + output_file + '"\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(trigger)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(trigger)} bytes)")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c
