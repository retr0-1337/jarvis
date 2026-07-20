"""Vulnerability schema definitions for Jarvis security database."""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "knowledge.json")

@dataclass
class TriggerPrimitives:
    """Exact values needed to trigger the vulnerability."""
    magic_bytes: Optional[str] = None
    overflow_value: Optional[str] = None
    entry_count: Optional[str] = None
    entry_size: Optional[int] = None
    offset: Optional[str] = None
    bad_value: Optional[str] = None
    overflow_field: Optional[str] = None
    custom: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FileAtom:
    """MP4/PDF/etc atom or object definition."""
    name: str
    vulnerable: bool = False
    overflow_field: Optional[str] = None
    children: List[str] = field(default_factory=list)
    payload_template: Optional[str] = None

@dataclass
class TargetFileStructure:
    """Structural layout of the target file format."""
    format: str
    atoms: List[FileAtom] = field(default_factory=list)
    vulnerable_atom: Optional[str] = None
    hierarchy: List[str] = field(default_factory=list)

@dataclass
class VulnerabilityEntry:
    """Complete vulnerability profile in the knowledge base."""
    cve_id: str
    vulnerability_type: str  # integer_overflow, buffer_overflow, use_after_free, etc.
    severity: str  # critical, high, medium, low
    target: str
    description: str
    trigger_primitives: TriggerPrimitives
    target_file_structure: Optional[TargetFileStructure] = None
    template_type: str = "generic"  # file_format, network, kernel, generic
    language: str = "python"
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "VulnerabilityEntry":
        tp = d.get("trigger_primitives", {})
        if isinstance(tp, dict):
            tp = TriggerPrimitives(**tp)
        fs = d.get("target_file_structure")
        if isinstance(fs, dict):
            atoms = [FileAtom(**a) for a in fs.get("atoms", [])]
            fs = TargetFileStructure(
                format=fs.get("format", ""),
                atoms=atoms,
                vulnerable_atom=fs.get("vulnerable_atom"),
                hierarchy=fs.get("hierarchy", []),
            )
        return cls(
            cve_id=d["cve_id"],
            vulnerability_type=d["vulnerability_type"],
            severity=d.get("severity", "high"),
            target=d["target"],
            description=d["description"],
            trigger_primitives=tp,
            target_file_structure=fs,
            template_type=d.get("template_type", "generic"),
            language=d.get("language", "python"),
            references=d.get("references", []),
        )

def load_database() -> List[VulnerabilityEntry]:
    if not os.path.exists(DB_PATH):
        return []
    with open(DB_PATH) as f:
        data = json.load(f)
    return [VulnerabilityEntry.from_dict(e) for e in data]

def save_database(entries: List[VulnerabilityEntry]):
    with open(DB_PATH, "w") as f:
        json.dump([e.to_dict() for e in entries], f, indent=2)

def lookup_cve(cve_id: str) -> Optional[VulnerabilityEntry]:
    entries = load_database()
    for e in entries:
        if e.cve_id == cve_id:
            return e
    return None

VULN_TYPE_KEYWORDS = {
    "integer_overflow": ["integer overflow", "int overflow", "overflow"],
    "buffer_overflow": ["buffer overflow", "stack overflow", "heap overflow", "overflow", "memcpy", "strcpy"],
    "use_after_free": ["use-after-free", "use after free", "uaf", "double free"],
    "format_string": ["format string", "printf", "sprintf"],
    "type_confusion": ["type confusion", "type混淆"],
    "out_of_bounds": ["out-of-bounds", "oob", "out of bounds", "ocean"],
    "race_condition": ["race condition", "race", "toctou"],
    "kernel_memory": ["kernel", "kernel memory", "local privilege escalation"],
    "file_format": ["file format", "parser", "media", "image", "document"],
    "network": ["network", "handshake", "protocol", "tcp", "http"],
}
