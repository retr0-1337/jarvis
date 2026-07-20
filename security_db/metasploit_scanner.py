"""Metasploit module scanner for Jarvis security database.

Scans Metasploit modules/exploits/ for Ruby exploit modules,
extracts metadata (Name, Description, CVE, Platform, Targets, Payload),
and synchronizes with jarvis_knowledge.json.
"""
import os
import re
import sys
import json
from typing import Dict, List, Optional, Any
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(__file__))
from schema import (
    VulnerabilityEntry, TriggerPrimitives, TargetFileStructure,
    FileAtom, load_database, save_database, DB_PATH
)

_MSF_BASE = os.environ.get("JARVIS_MSF_PATH", "/opt/metasploit/modules/exploits")
MSF_PATH = _MSF_BASE

# Metasploit module class hierarchy for categorization
MODULE_TYPE_MAP = {
    "Msf::Exploit::Remote::HttpServer::HTML": "browser",
    "Msf::Exploit::Remote::HttpClient": "network",
    "Msf::Exploit::Remote::Tcp": "network",
    "Msf::Exploit::Remote::SMB": "network",
    "Msf::Exploit::Remote::Ftp": "network",
    "Msf::Exploit::Remote::SSH": "network",
    "Msf::Exploit::Remote::Daemon": "network",
    "Msf::Exploit::FileDropper": "file_format",
    "Msf::Exploit::Local": "local",
    "Msf::Exploit::EXE": "binary",
}

PLATFORM_VULN_TYPE = {
    "android": "file_format",
    "linux": "kernel_memory",
    "windows": "buffer_overflow",
    "osx": "buffer_overflow",
    "multi": "generic",
    "unix": "generic",
}


def parse_ruby_string(text: str, start: int) -> tuple:
    """Extract a Ruby string from single-quoted, double-quoted, or %q{} notation."""
    if start >= len(text):
        return "", start

    # %q{...} notation
    if text[start:start+3] in ("%q{", "%Q{"):
        opener = text[start+2]
        closer = "}" if opener == "{" else opener
        depth = 1
        i = start + 3
        while i < len(text) and depth > 0:
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == closer:
                depth -= 1
            if text[i] == opener and closer != "{":
                depth += 1
            i += 1
        return text[start+3:i-1].strip(), i

    # Single-quoted
    if text[start] == "'":
        i = start + 1
        while i < len(text):
            if text[i] == "\\" and i + 1 < len(text):
                i += 2
                continue
            if text[i] == "'":
                return text[start+1:i], i + 1
            i += 1
        return text[start+1:], len(text)

    # Double-quoted
    if text[start] == '"':
        i = start + 1
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == '"':
                return text[start+1:i], i + 1
            i += 1
        return text[start+1:], len(text)

    return "", start


def extract_metadata(content: str, filepath: str) -> Dict[str, Any]:
    """Extract metadata from a Metasploit Ruby module.

    Args:
        content: Full Ruby source code
        filepath: Path to the .rb file

    Returns:
        Dictionary with extracted metadata
    """
    meta = {
        "name": "",
        "description": "",
        "cves": [],
        "platform": "",
        "arch": [],
        "targets": [],
        "payload_space": None,
        "payload_restrictions": [],
        "rank": "",
        "module_type": "exploit",
        "references": [],
    }

    # Extract module class hierarchy
    class_match = re.search(r'class\s+\w+\s*<\s*(Msf::\S+)', content)
    if class_match:
        parent = class_match.group(1)
        for pattern, mtype in MODULE_TYPE_MAP.items():
            if pattern in parent:
                meta["module_type"] = mtype
                break

    # Extract Name
    name_match = re.search(r"'Name'\s*=>\s*", content)
    if name_match:
        s, e = parse_ruby_string(content, name_match.end())
        meta["name"] = s

    # Extract Description
    desc_match = re.search(r"'Description'\s*=>\s*", content)
    if desc_match:
        s, e = parse_ruby_string(content, desc_match.end())
        meta["description"] = s

    # Extract References (CVEs, URLs, etc)
    refs_match = re.search(r"'References'\s*=>\s*\[", content)
    if refs_match:
        i = refs_match.end()
        depth = 1
        refs_text = ""
        while i < len(content) and depth > 0:
            if content[i] == "[":
                depth += 1
            elif content[i] == "]":
                depth -= 1
            if depth > 0:
                refs_text += content[i]
            i += 1

        # Extract CVEs
        cve_pattern = re.findall(r"\[\s*'CVE'\s*,\s*'(\d{4}-\d+)'\s*\]", refs_text)
        meta["cves"] = [f"CVE-{c}" for c in cve_pattern]

        # Extract other references
        url_pattern = re.findall(r"\[\s*'URL'\s*,\s*'([^']+)'\s*\]", refs_text)
        meta["references"] = url_pattern

    # Extract Platform
    plat_match = re.search(r"'Platform'\s*=>\s*'([^']+)'", content)
    if plat_match:
        meta["platform"] = plat_match.group(1)

    # Extract Arch
    arch_match = re.search(r"'Arch'\s*=>\s*\[([^\]]+)\]", content)
    if arch_match:
        arches = re.findall(r'ARCH_\w+', arch_match.group(1))
        meta["arch"] = arches

    # Extract Payload info
    payload_match = re.search(r"'Payload'\s*=>\s*\{([^}]+)\}", content)
    if payload_match:
        payload_text = payload_match.group(1)
        space_match = re.search(r"'Space'\s*=>\s*(\d+)", payload_text)
        if space_match:
            meta["payload_space"] = int(space_match.group(1))
        if "DisableNops" in payload_text:
            meta["payload_restrictions"].append("no_nops")
        if "BadChars" in payload_text:
            bad_match = re.search(r"'BadChars'\s*=>\s*'([^']+)'", payload_text)
            if bad_match:
                meta["payload_restrictions"].append(f"bad_chars:{bad_match.group(1)}")

    # Extract Rank
    rank_match = re.search(r'Rank\s*=\s*(\w+Ranking)', content)
    if rank_match:
        meta["rank"] = rank_match.group(1)

    # Extract Targets
    targets_match = re.search(r"'Targets'\s*=>\s*\[", content)
    if targets_match:
        i = targets_match.end()
        depth = 1
        targets_text = ""
        while i < len(content) and depth > 0:
            if content[i] == "[":
                depth += 1
            elif content[i] == "]":
                depth -= 1
            if depth > 0:
                targets_text += content[i]
            i += 1

        # Parse individual targets
        target_entries = re.findall(r"\[\s*'([^']+)'", targets_text)
        meta["targets"] = target_entries

    # Extract default options (payload selection)
    default_opts_match = re.search(r"'DefaultOptions'\s*=>\s*\{([^}]+)\}", content)
    if default_opts_match:
        opts_text = default_opts_match.group(1)
        payload_default = re.search(r"'PAYLOAD'\s*=>\s*'([^']+)'", opts_text)
        if payload_default:
            meta["default_payload"] = payload_default.group(1)

    return meta


def classify_vuln_from_msf(meta: Dict[str, Any]) -> str:
    """Classify vulnerability type from Metasploit metadata."""
    name_lower = meta["name"].lower()
    desc_lower = meta["description"].lower()
    platform = meta["platform"].lower()

    # Check for specific vulnerability types
    if any(kw in name_lower or kw in desc_lower for kw in ["integer overflow", "int overflow"]):
        return "integer_overflow"
    if any(kw in name_lower or kw in desc_lower for kw in ["buffer overflow", "stack overflow", "heap overflow"]):
        return "buffer_overflow"
    if any(kw in name_lower or kw in desc_lower for kw in ["use-after-free", "use after free", "uaf"]):
        return "use_after_free"
    if any(kw in name_lower or kw in desc_lower for kw in ["format string", "sprintf"]):
        return "format_string"
    if any(kw in name_lower or kw in desc_lower for kw in ["type confusion"]):
        return "type_confusion"
    if any(kw in name_lower or kw in desc_lower for kw in ["out-of-bounds", "oob", "out of bounds"]):
        return "out_of_bounds"
    if any(kw in name_lower for kw in ["fileformat", "file format", "mp4", "pdf", "doc"]):
        return "file_format"
    if any(kw in name_lower for kw in ["browser", "chrome", "firefox", "ie"]):
        return "browser_exploit"
    if platform in ("android", "linux") and meta["module_type"] in ("local", "kernel_memory"):
        return "kernel_memory"
    if any(kw in name_lower for kw in ["rce", "remote code", "command inject"]):
        return "remote_code_execution"

    # Default based on module type
    type_map = {
        "browser": "browser_exploit",
        "file_format": "file_format",
        "network": "network_exploit",
        "local": "kernel_memory",
    }
    return type_map.get(meta["module_type"], "generic")


def extract_trigger_from_msf(meta: Dict[str, Any]) -> TriggerPrimitives:
    """Extract trigger primitives from Metasploit metadata."""
    tp = TriggerPrimitives()
    name_lower = meta["name"].lower()

    if "integer overflow" in name_lower:
        tp.entry_count = "0x40000000"
        tp.entry_size = 12
        tp.overflow_value = "0x40000000"
        tp.overflow_field = "num_entries"
    elif "buffer overflow" in name_lower:
        tp.bad_value = "0x41" * 256
        tp.offset = "0x100"
        tp.overflow_value = "0x1000"
    elif "use-after-free" in name_lower or "uaf" in name_lower:
        tp.custom["free_call"] = "target_object"
        tp.custom["use_call"] = "target_object"
    elif "format string" in name_lower:
        tp.overflow_value = "%x%x%x%x"
    else:
        tp.overflow_value = "0x41414141"

    # Add payload space if known
    if meta.get("payload_space"):
        tp.custom["payload_space"] = meta["payload_space"]

    return tp


def build_file_structure_from_msf(meta: Dict[str, Any]) -> Optional[TargetFileStructure]:
    """Build file structure from Metasploit metadata if it's a file format exploit."""
    name_lower = meta["name"].lower()
    platform = meta["platform"].lower()

    # MP4/Stagefright
    if any(kw in name_lower for kw in ["mp4", "stagefright", "tx3g"]):
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
                FileAtom(name="tx3g", vulnerable=True, overflow_field="size_sum"),
            ],
            vulnerable_atom="tx3g",
            hierarchy=["ftyp", "moov", "trak", "mdia", "minf", "stbl"],
        )

    # PDF
    if any(kw in name_lower for kw in ["pdf", "acrobat"]):
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

    # DOC/DOCX
    if any(kw in name_lower for kw in ["doc", "word", "rtf"]):
        return TargetFileStructure(
            format="OLE",
            atoms=[
                FileAtom(name="OLE_HEADER"),
                FileAtom(name="Directory"),
                FileAtom(name="Stream"),
            ],
            vulnerable_atom="Stream",
            hierarchy=["header", "directory", "streams"],
        )

    # ELF
    if platform in ("linux", "android") and "elf" in name_lower:
        return TargetFileStructure(
            format="ELF",
            atoms=[
                FileAtom(name="elf_header"),
                FileAtom(name="program_headers"),
                FileAtom(name="section_headers"),
            ],
            vulnerable_atom="section_headers",
            hierarchy=["elf_header", "program_headers", "sections"],
        )

    return None


def scan_modules(msf_path: str = MSF_PATH) -> List[Dict[str, Any]]:
    """Scan Metasploit modules directory for all .rb exploit files.

    Args:
        msf_path: Path to Metasploit modules/exploits directory

    Returns:
        List of extracted metadata dictionaries
    """
    results = []
    if not os.path.exists(msf_path):
        print(f"[MSF] Path not found: {msf_path}", file=sys.stderr)
        return results

    rb_files = []
    for root, dirs, files in os.walk(msf_path):
        for f in files:
            if f.endswith(".rb") and not f.startswith("example"):
                rb_files.append(os.path.join(root, f))

    print(f"[MSF] Found {len(rb_files)} Ruby modules to scan", file=sys.stderr)

    for i, filepath in enumerate(rb_files):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            meta = extract_metadata(content, filepath)

            # Calculate relative module path from exploits/
            rel_path = os.path.relpath(filepath, msf_path)
            module_path = "exploits/" + rel_path.replace(".rb", "").replace(os.sep, "/")

            meta["module_path"] = module_path
            meta["file_path"] = filepath

            if meta["name"]:  # Only add if we extracted a name
                results.append(meta)

            if (i + 1) % 100 == 0:
                print(f"[MSF] Processed {i+1}/{len(rb_files)}", file=sys.stderr)

        except Exception as e:
            print(f"[MSF] Error parsing {filepath}: {e}", file=sys.stderr)

    print(f"[MSF] Extracted metadata from {len(results)} modules", file=sys.stderr)
    return results


def sync_with_database(modules: List[Dict[str, Any]]) -> int:
    """Synchronize Metasploit modules with jarvis_knowledge.json.

    Cross-references CVEs and adds Metasploit module paths to existing entries.
    Creates new entries for modules without existing CVE matches.

    Args:
        modules: List of extracted Metasploit metadata

    Returns:
        Number of new entries added
    """
    existing = load_database()
    existing_by_cve = {}
    for e in existing:
        for cve in [e.cve_id]:
            existing_by_cve[cve] = e
        # Also index by description keywords
        existing_by_cve[e.description[:50].lower()] = e

    new_count = 0
    updated_count = 0

    for meta in modules:
        cves = meta.get("cves", [])
        vuln_type = classify_vuln_from_msf(meta)
        trigger = extract_trigger_from_msf(meta)
        file_struct = build_file_structure_from_msf(meta)

        # Try to match existing entry by CVE
        matched = False
        for cve_id in cves:
            if cve_id in existing_by_cve:
                entry = existing_by_cve[cve_id]
                # Update with Metasploit module path
                entry.description = meta["description"][:500]
                if not entry.target_file_structure and file_struct:
                    entry.target_file_structure = file_struct
                entry.trigger_primitives = trigger
                entry.trigger_primitives.custom["metasploit_module"] = meta["module_path"]
                updated_count += 1
                matched = True
                break

        if not matched and cves:
            # Create new entry for unmatched CVEs
            entry = VulnerabilityEntry(
                cve_id=cves[0],
                vulnerability_type=vuln_type,
                severity="high",
                target=meta["platform"] or "unknown",
                description=meta["description"][:500],
                trigger_primitives=trigger,
                target_file_structure=file_struct,
                template_type="file_format" if file_struct else "generic",
                references=meta.get("references", [])[:5],
            )
            # Store Metasploit module path in custom field
            entry.trigger_primitives.custom["metasploit_module"] = meta["module_path"]
            existing.append(entry)
            new_count += 1

        elif not cves and meta["name"]:
            # Module without CVE — create entry with module path as identifier
            fake_cve = f"MSF-{meta['module_path'].replace('/', '-').replace('exploits-', '')}"
            entry = VulnerabilityEntry(
                cve_id=fake_cve,
                vulnerability_type=vuln_type,
                severity="medium",
                target=meta["platform"] or "unknown",
                description=meta["description"][:500],
                trigger_primitives=trigger,
                target_file_structure=file_struct,
                template_type="file_format" if file_struct else "generic",
                references=meta.get("references", [])[:5],
            )
            entry.trigger_primitives.custom["metasploit_module"] = meta["module_path"]
            entry.trigger_primitives.custom["msf_name"] = meta["name"]
            existing.append(entry)
            new_count += 1

    save_database(existing)
    print(f"[MSF] Sync complete: {updated_count} updated, {new_count} new entries", file=sys.stderr)
    return new_count


def run_scanner() -> Dict[str, Any]:
    """Run the full Metasploit scanning and synchronization pipeline.

    Returns:
        Summary of scan results
    """
    modules = scan_modules()
    new_entries = sync_with_database(modules)

    # Build summary
    cve_count = sum(1 for m in modules if m.get("cves"))
    no_cve_count = len(modules) - cve_count

    type_counts = {}
    for m in modules:
        vtype = classify_vuln_from_msf(m)
        type_counts[vtype] = type_counts.get(vtype, 0) + 1

    summary = {
        "total_modules": len(modules),
        "with_cves": cve_count,
        "without_cves": no_cve_count,
        "new_entries": new_entries,
        "vuln_types": type_counts,
        "platforms": {},
    }

    for m in modules:
        plat = m.get("platform", "unknown")
        summary["platforms"][plat] = summary["platforms"].get(plat, 0) + 1

    return summary


if __name__ == "__main__":
    summary = run_scanner()
    print(json.dumps(summary, indent=2))
