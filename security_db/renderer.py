"""Template renderer for Jarvis security database.

Takes a validated CVE profile and programmatically generates a syntactically
correct Python PoC file generator using class-based TLV packaging.
"""
import os
import sys
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(__file__))

from schema import VulnerabilityEntry, load_database, lookup_cve

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


def import_template(template_type: str):
    """Import the appropriate template module."""
    if template_type == "integer_overflow":
        from templates.integer_overflow import render_integer_overflow
        return render_integer_overflow
    elif template_type == "buffer_overflow":
        from templates.buffer_overflow import render_buffer_overflow
        return render_buffer_overflow
    elif template_type == "use_after_free":
        from templates.use_after_free import render_use_after_free
        return render_use_after_free
    elif template_type == "file_format":
        from templates.file_format import render_file_format
        return render_file_format
    else:
        from templates.generic import render_generic
        return render_generic


def render_code(vuln: VulnerabilityEntry) -> str:
    """Render a complete Python PoC from a vulnerability profile.

    Args:
        vuln: Validated vulnerability entry from knowledge base

    Returns:
        Complete Python source code string
    """
    vuln_dict = vuln.to_dict()
    render_fn = import_template(vuln.template_type)
    code = render_fn(vuln_dict)
    return code


def render_from_dict(vuln_dict: Dict[str, Any]) -> str:
    """Render code directly from a dictionary (for bridge integration).

    Args:
        vuln_dict: Dictionary matching VulnerabilityEntry schema

    Returns:
        Complete Python source code string
    """
    vuln = VulnerabilityEntry.from_dict(vuln_dict)
    render_fn = import_template(vuln.template_type)
    code = render_fn(vuln_dict)
    return code


def render_by_cve(cve_id: str) -> Optional[str]:
    """Look up a CVE and render its PoC code.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2015-1538")

    Returns:
        Python source code or None if CVE not found
    """
    vuln = lookup_cve(cve_id)
    if not vuln:
        return None
    return render_code(vuln)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python renderer.py <CVE-ID>")
        print("Example: python renderer.py CVE-2015-1538")
        sys.exit(1)

    cve_id = sys.argv[1]
    code = render_by_cve(cve_id)
    if code:
        print(code)
    else:
        print(f"Error: {cve_id} not found in knowledge base", file=sys.stderr)
        sys.exit(1)
