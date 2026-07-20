"""Use-after-free exploit template for Jarvis."""
from typing import Dict, Any


def render_use_after_free(vuln: Dict[str, Any]) -> str:
    trigger = vuln.get("trigger_primitives", {})
    custom = trigger.get("custom", {})
    free_call = custom.get("free_call", "target_object")
    use_call = custom.get("use_call", "target_object")
    target = vuln.get("target", "target_binary")
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    description = vuln.get("description", "")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".bin"

    c = '#!/usr/bin/env python3\n'
    c += '"""Use-after-free PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n'
    c += '\n'
    c += 'Mechanism: Free object at ' + free_call + ', then reuse at ' + use_call + '\n'
    c += '"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'class UseAfterFree:\n'
    c += '    """Construct the use-after-free trigger.\n\n'
    c += '    1. Allocate target object\n'
    c += '    2. Free target object\n'
    c += '    3. Reallocate with controlled data\n'
    c += '    4. Use the freed pointer\n'
    c += '    """\n\n'
    c += '    def __init__(self):\n'
    c += '        self.free_call = "' + free_call + '"\n'
    c += '        self.use_call = "' + use_call + '"\n'
    c += '        self.object_size = 256\n'
    c += '        self.fill_byte = 0x41\n\n'
    c += '    def build_trigger(self) -> bytes:\n'
    c += '        data = bytes([self.fill_byte] * self.object_size)\n'
    c += '        return data\n\n\n'
    c += 'def main():\n'
    c += '    uaf = UseAfterFree()\n'
    c += '    trigger = uaf.build_trigger()\n'
    c += '    output = "' + output_file + '"\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(trigger)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(trigger)} bytes)")\n'
    c += '    print(f"[*] Free: {uaf.free_call}")\n'
    c += '    print(f"[*] Use: {uaf.use_call}")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c
