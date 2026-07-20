"""CISA KEV + NVD ingestion engine for Jarvis security database."""
import json
import os
import sys
import time
import requests
from typing import List, Optional
from schema import (
    VulnerabilityEntry, TriggerPrimitives, TargetFileStructure,
    FileAtom, VULN_TYPE_KEYWORDS, load_database, save_database
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEYWORDS = [
    "overflow", "memory corruption", "use-after-free", "buffer",
    "kernel", "privilege escalation", "arbitrary write", "heap",
    "integer overflow", "out-of-bounds", "format string",
    "type confusion", "file format", "parser", "media",
    "stagefright", "libstagefright", "pdf", "image", "font",
    "glibc", "jemalloc", "ptmalloc", "malloc", "free",
    "socket", "tcp", "http", "handshake", "tls", "ssl",
    "arm", "arm64", "x86", "x64", "mips", "riscv",
    "shellcode", "rop", "jop", "stack pivot",
    "sandbox", "container", "docker", "namespace",
    "netfilter", "iptables", "seccomp", "selinux", "apparmor",
]

OVERFLOW_TRIGGERS = {
    "integer_overflow": "0x40000000",
    "buffer_overflow": "0x1000",
    "heap_overflow": "0x1000",
    "stack_overflow": "0x400",
    "use_after_free": "free_double",
    "out_of_bounds": "0xFFFFFFFF",
    "type_confusion": "type_mismatch",
    "format_string": "%x%x%x%x",
    "kernel_memory": "0x41414141",
    "file_format": "0x40000000",
    "network": "0x41414141",
}

TEMPLATE_MAP = {
    "integer_overflow": "integer_overflow",
    "buffer_overflow": "buffer_overflow",
    "heap_overflow": "buffer_overflow",
    "stack_overflow": "buffer_overflow",
    "use_after_free": "use_after_free",
    "out_of_bounds": "buffer_overflow",
    "type_confusion": "use_after_free",
    "format_string": "generic",
    "kernel_memory": "generic",
    "file_format": "file_format",
    "network": "generic",
}

def classify_vuln(description: str) -> str:
    desc_lower = description.lower()
    best_type = "generic"
    best_score = 0
    for vtype, kws in VULN_TYPE_KEYWORDS.items():
        score = sum(1 for kw in kws if kw in desc_lower)
        if score > best_score:
            best_score = score
            best_type = vtype
    return best_type

def extract_trigger(vtype: str, description: str) -> TriggerPrimitives:
    tp = TriggerPrimitives()
    tp.overflow_value = OVERFLOW_TRIGGERS.get(vtype, "0x41414141")
    if vtype == "integer_overflow":
        tp.entry_count = "0x40000000"
        tp.entry_size = 12
        tp.overflow_field = "num_entries"
    elif vtype in ("buffer_overflow", "heap_overflow", "stack_overflow"):
        tp.bad_value = "0x41" * 256
        tp.offset = "0x100"
    elif vtype == "use_after_free":
        tp.custom["free_call"] = "target_object"
        tp.custom["use_call"] = "target_object"
    elif vtype == "file_format":
        tp.entry_count = "0x40000000"
        tp.entry_size = 12
    elif vtype == "kernel_memory":
        tp.offset = "0x41414141"
        tp.custom["target_pid"] = "self"
    return tp

def build_file_structure(vtype: str, description: str) -> Optional[TargetFileStructure]:
    desc_lower = description.lower()
    if "mp4" in desc_lower or "stagefright" in desc_lower or "media" in desc_lower:
        return TargetFileStructure(
            format="MP4",
            atoms=[
                FileAtom(name="ftyp"),
                FileAtom(name="moov", children=["mvhd", "trak"]),
                FileAtom(name="trak", children=["tkhd", "mdia"]),
                FileAtom(name="mdia", children=["mdhd", "hdlr", "minf"]),
                FileAtom(name="minf", children=["vmhd", "dinf", "stbl"]),
                FileAtom(name="stbl", children=["stsd", "stts", "stsc", "stsz", "stco"]),
                FileAtom(name="stsc", vulnerable=True, overflow_field="sample_count"),
            ],
            vulnerable_atom="stsc",
            hierarchy=["ftyp", "moov", "trak", "mdia", "minf", "stbl", "stsc"],
        )
    elif "pdf" in desc_lower:
        return TargetFileStructure(
            format="PDF",
            atoms=[
                FileAtom(name="%PDF-1.4"),
                FileAtom(name="obj", children=["stream", "endobj"]),
                FileAtom(name="xref"),
                FileAtom(name="trailer"),
            ],
            vulnerable_atom="stream",
            hierarchy=["header", "objects", "xref", "trailer"],
        )
    elif "elf" in desc_lower or "binary" in desc_lower:
        return TargetFileStructure(
            format="ELF",
            atoms=[
                FileAtom(name="elf_header"),
                FileAtom(name="program_headers"),
                FileAtom(name="section_headers"),
                FileAtom(name="symtab"),
            ],
            vulnerable_atom="section_headers",
            hierarchy=["elf_header", "program_headers", "sections"],
        )
    return None

def fetch_cisa_kev() -> List[dict]:
    print("[INGEST] Fetching CISA KEV...", file=sys.stderr)
    try:
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        print(f"[INGEST] Got {len(vulns)} entries from KEV", file=sys.stderr)
        return vulns
    except Exception as e:
        print(f"[INGEST] KEV fetch failed: {e}", file=sys.stderr)
        return []

def fetch_nvd(cve_id: str) -> Optional[dict]:
    try:
        url = f"{NVD_API}?cveId={cve_id}"
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except Exception:
        pass
    return None

def filter_relevant(kev_entries: List[dict]) -> List[dict]:
    relevant = []
    for v in kev_entries:
        desc = v.get("shortDescription", "").lower()
        vuln_id = v.get("cveID", "")
        if any(kw in desc for kw in KEYWORDS):
            relevant.append(v)
    print(f"[INGEST] Filtered to {len(relevant)} relevant CVEs", file=sys.stderr)
    return relevant

def ingest() -> List[VulnerabilityEntry]:
    existing = load_database()
    existing_ids = {e.cve_id for e in existing}

    kev_entries = fetch_cisa_kev()
    if not kev_entries:
        print("[INGEST] No KEV data, using existing database", file=sys.stderr)
        return existing

    relevant = filter_relevant(kev_entries)
    new_entries = []

    for v in relevant[:100]:
        cve_id = v.get("cveID", "")
        if cve_id in existing_ids:
            continue

        desc = v.get("shortDescription", "")
        vtype = classify_vuln(desc)
        trigger = extract_trigger(vtype, desc)
        file_struct = build_file_structure(vtype, desc)
        severity = v.get("dateAdded", "")

        entry = VulnerabilityEntry(
            cve_id=cve_id,
            vulnerability_type=vtype,
            severity="high",
            target=v.get("vendorProject", "unknown"),
            description=desc[:500],
            trigger_primitives=trigger,
            target_file_structure=file_struct,
            template_type=TEMPLATE_MAP.get(vtype, "generic"),
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        )
        new_entries.append(entry)
        existing_ids.add(cve_id)
        time.sleep(0.1)

    all_entries = existing + new_entries
    save_database(all_entries)
    print(f"[INGEST] Added {len(new_entries)} new entries, total: {len(all_entries)}", file=sys.stderr)
    return all_entries

if __name__ == "__main__":
    ingest()
