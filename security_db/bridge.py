"""Reasoning injector bridge for Jarvis security database.

Lookup interface: When Jarvis is queried about a specific CVE, this module
automatically reads the local JSON schema file and feeds validated data
directly into the renderer, completely bypassing the LLM's own text
generation for binary data.
"""
import os
import sys
import json
from typing import Optional, Dict, Any, List

sys.path.insert(0, os.path.dirname(__file__))

from schema import (
    VulnerabilityEntry, TriggerPrimitives, TargetFileStructure,
    FileAtom, load_database, lookup_cve, save_database
)
from renderer import render_code, render_from_dict
from ranker import ExploitRanker, rank_exploits
from profiler import (
    parse_user_profile, format_profile, list_presets,
    PRESET_PROFILES, get_profile_questions
)
from guide import generate_guide, AdaptationGuide


class SecurityBridge:
    """Bridge between CVE queries and template-based code generation.

    This module ensures the LLM never generates binary data directly.
    Instead, it:
    1. Looks up the CVE in the local knowledge base
    2. Loads the validated trigger primitives and file structure
    3. Feeds them into the template renderer
    4. Returns the complete, runnable Python code
    """

    def __init__(self):
        self.db = load_database()

    def lookup(self, query: str) -> Optional[Dict[str, Any]]:
        """Search the knowledge base for a CVE.

        Args:
            query: CVE ID (e.g., "CVE-2015-1538") or keyword search

        Returns:
            Dictionary with vulnerability data, or None
        """
        query_upper = query.upper().strip()

        if query_upper.startswith("CVE-"):
            vuln = lookup_cve(query_upper)
            if vuln:
                return vuln.to_dict()

        query_lower = query.lower()
        for entry in self.db:
            if (query_lower in entry.cve_id.lower() or
                query_lower in entry.description.lower() or
                query_lower in entry.target.lower()):
                return entry.to_dict()

        return None

    def generate_poc(self, query: str) -> Optional[str]:
        """Look up a CVE and generate a complete PoC.

        Args:
            query: CVE ID or keyword search

        Returns:
            Complete Python source code, or None if not found
        """
        vuln_dict = self.lookup(query)
        if not vuln_dict:
            return None

        try:
            code = render_from_dict(vuln_dict)
            return code
        except Exception as e:
            print(f"[BRIDGE] Render error: {e}", file=sys.stderr)
            return None

    def get_vulnerability_info(self, query: str) -> Optional[str]:
        """Get structured vulnerability information for LLM context.

        This provides the LLM with validated data to discuss the vulnerability,
        without letting it generate binary payloads.

        Args:
            query: CVE ID or keyword search

        Returns:
            Formatted vulnerability information string
        """
        vuln_dict = self.lookup(query)
        if not vuln_dict:
            return None

        tp = vuln_dict.get("trigger_primitives", {})
        fs = vuln_dict.get("target_file_structure")

        info = f"## {vuln_dict.get('cve_id', 'Unknown')}\n"
        info += f"**Type:** {vuln_dict.get('vulnerability_type', 'unknown')}\n"
        info += f"**Target:** {vuln_dict.get('target', 'unknown')}\n"
        info += f"**Description:** {vuln_dict.get('description', 'N/A')}\n\n"

        info += "### Trigger Primitives\n"
        for k, v in tp.items():
            if v:
                info += f"- `{k}`: `{v}`\n"

        if fs:
            info += f"\n### File Structure ({fs.get('format', 'unknown')})\n"
            info += f"Vulnerable atom: `{fs.get('vulnerable_atom', 'N/A')}`\n"
            atoms = fs.get("atoms", [])
            if atoms:
                info += "Hierarchy:\n"
                for atom in atoms:
                    name = atom.get("name", "unknown")
                    vuln_marker = " [VULNERABLE]" if atom.get("vulnerable") else ""
                    info += f"  - `{name}`{vuln_marker}\n"

        return info

    def explain_cve(self, cve_id: str) -> Optional[str]:
        """Generate a styled HTML explanation for a CVE."""
        vuln_dict = self.lookup(cve_id)
        if not vuln_dict:
            return None

        tp = vuln_dict.get("trigger_primitives", {})
        fs = vuln_dict.get("target_file_structure")
        custom = tp.get("custom", {})
        msf = custom.get("metasploit_module", "")
        refs = vuln_dict.get("references", [])
        desc = vuln_dict.get("description", "No description available.")
        vtype = vuln_dict.get("vulnerability_type", "unknown")
        severity = vuln_dict.get("severity", "unknown")
        target = vuln_dict.get("target", "unknown")

        sev_cls = "sev-" + severity

        h = []
        # TTS comment: plain text for speech synthesis (stripped of HTML)
        tts_text = f"{cve_id}. {desc}"
        h.append(f'<!--EXPLOIT_START--><!--TTS:{tts_text}-->')
        h.append('<div class="cve-explain">')
        h.append(f'<div class="cve-explain-header"><h1>{cve_id}</h1>')
        h.append(f'<div class="exploit-meta"><span class="exploit-type">{vtype}</span><span class="exploit-severity {sev_cls}">{severity}</span><span class="exploit-target">{target}</span></div>')
        h.append('</div>')

        h.append('<div class="guide-section"><h2>Description</h2>')
        h.append(f'<p>{desc}</p>')
        h.append('</div>')

        # Trigger analysis
        h.append('<div class="guide-section"><h2>How It Works</h2>')
        if vtype == "integer_overflow" and tp.get("entry_count") and tp.get("entry_size"):
            ec = tp["entry_count"]
            es = tp["entry_size"]
            try:
                ec_int = int(ec, 0)
                overflow = ec_int * es
                wrapped = overflow & 0xFFFFFFFF
                h.append(f'<p>An integer overflow occurs when the entry count <code>{ec}</code> is multiplied by the entry size <code>{es}</code>.</p>')
                h.append(f'<p><code>{ec} &times; {es} = 0x{overflow:X}</code>, which wraps to <code>0x{wrapped:08X}</code> in 32-bit arithmetic.</p>')
                h.append(f'<p>This causes an undersized buffer allocation, leading to heap corruption when data is written beyond the allocated space.</p>')
            except ValueError:
                h.append(f'<p>Trigger: {ec} &times; {es} causes an integer overflow in size calculation.</p>')
        elif vtype == "buffer_overflow":
            offset = tp.get("offset", "unknown")
            h.append(f'<p>A buffer overflow occurs at offset <code>{offset}</code>, allowing overwrite of critical memory (saved return address, function pointer, etc.).</p>')
        elif vtype == "use_after_free":
            h.append('<p>An object is freed but a dangling pointer remains. By spraying the heap with controlled data, the attacker reclaims the freed memory and hijacks execution when the dangling pointer is used.</p>')
        elif vtype == "kernel_memory":
            h.append(f'<p>A logic flaw in the kernel allows an unprivileged user to corrupt kernel memory through a specific sequence of system calls.</p>')
            if msf:
                h.append(f'<p>The Metasploit module <code>{msf}</code> automates exploitation of this vulnerability.</p>')
        elif vtype == "remote_code_execution":
            h.append('<p>Remote code execution is achieved through memory corruption or a logic flaw, allowing an attacker to inject and execute arbitrary code.</p>')
        else:
            h.append(f'<p>This is a {vtype} vulnerability. Analyze the specific trigger mechanism for detailed exploitation steps.</p>')
        h.append('</div>')

        # Trigger primitives
        primitives = {k: v for k, v in tp.items() if v and k != "custom"}
        if primitives:
            h.append('<div class="guide-section"><h2>Trigger Primitives</h2>')
            h.append('<div class="vuln-details">')
            for k, v in primitives.items():
                label = k.replace("_", " ").title()
                h.append(f'<div class="vuln-detail"><span class="vuln-label">{label}:</span><code>{v}</code></div>')
            h.append('</div></div>')

        # File structure (for file format exploits)
        if fs:
            h.append(f'<div class="guide-section"><h2>File Format: {fs.get("format", "unknown")}</h2>')
            h.append(f'<p>Vulnerable atom: <code>{fs.get("vulnerable_atom", "N/A")}</code></p>')
            atoms = fs.get("atoms", [])
            if atoms:
                h.append('<ul>')
                for atom in atoms:
                    name = atom.get("name", "?")
                    marker = ' <span class="exploit-severity sev-high">VULNERABLE</span>' if atom.get("vulnerable") else ""
                    h.append(f'<li><code>{name}</code>{marker}</li>')
                h.append('</ul>')
            h.append('</div>')

        # Impact
        h.append('<div class="guide-section"><h2>Impact</h2>')
        if "kernel" in vtype or "local" in (msf or ""):
            h.append('<p>Local privilege escalation &mdash; an unprivileged user can gain root or kernel-level access on the affected system.</p>')
        elif "remote" in vtype:
            h.append('<p>Remote code execution &mdash; an attacker can execute arbitrary code on the target system without authentication.</p>')
        else:
            h.append('<p>Successful exploitation may lead to privilege escalation, code execution, or denial of service.</p>')
        h.append('</div>')

        # References
        if refs:
            h.append('<div class="guide-section"><h2>References</h2><ul>')
            for ref in refs[:5]:
                h.append(f'<li><code>{ref}</code></li>')
            h.append('</ul></div>')

        # MSF module
        if msf:
            h.append('<div class="guide-section"><h2>Metasploit Module</h2>')
            h.append(f'<div class="exploit-msf"><span class="msf-label">Module</span><code>{msf}</code></div>')
            h.append('<pre><code>msfconsole')
            h.append(f'use {msf}')
            h.append('show options')
            h.append('exploit')
            h.append('</code></pre></div>')

        h.append('</div><!--EXPLOIT_END-->')
        return "\n".join(h)

    def list_vulnerabilities(self, keyword: Optional[str] = None) -> list:
        """List all vulnerabilities in the database, optionally filtered.

        Args:
            keyword: Optional keyword filter

        Returns:
            List of vulnerability summaries
        """
        results = []
        for entry in self.db:
            if keyword and keyword.lower() not in entry.description.lower():
                continue
            results.append({
                "cve_id": entry.cve_id,
                "type": entry.vulnerability_type,
                "target": entry.target,
                "template_type": entry.template_type,
            })
        return results

    def ingest(self) -> int:
        """Run the ingestion engine to populate/update the database.

        Returns:
            Number of entries in the database after ingestion
        """
        from ingestion import ingest
        entries = ingest()
        self.db = entries
        return len(entries)

    # --- NEW: Intelligence methods ---

    def rank_exploits_for_target(self, target_os: str, target_arch: str = "",
                                 vuln_type: str = "", category: str = "",
                                 top_n: int = 5) -> str:
        """Rank exploits for a specific target platform.

        Args:
            target_os: Target OS (android, linux, windows, etc.)
            target_arch: Target architecture (arm64, x86_64, etc.)
            vuln_type: Optional vulnerability type filter
            category: Optional device category (router, browser, etc.)
            top_n: Number of results to return

        Returns:
            Formatted ranking of exploits with scores
        """
        return rank_exploits(target_os=target_os, target_arch=target_arch,
                           vuln_type=vuln_type, category=category, top_n=top_n)

    def get_adaptation_guide(self, cve_id: str, target_profile: Dict[str, Any]) -> Optional[str]:
        """Generate an adaptation guide for a CVE against a specific target.

        Args:
            cve_id: CVE identifier
            target_profile: Target environment details

        Returns:
            Step-by-step adaptation guide
        """
        entry = lookup_cve(cve_id)
        if not entry:
            return None
        return generate_guide(entry, target_profile)

    def get_guide_for_preset(self, cve_id: str, preset_name: str) -> Optional[str]:
        """Generate adaptation guide using a preset profile.

        Args:
            cve_id: CVE identifier
            preset_name: Preset profile name (e.g., 'android_modern', 'linux_server')

        Returns:
            Step-by-step adaptation guide
        """
        entry = lookup_cve(cve_id)
        if not entry:
            return None

        profile = PRESET_PROFILES.get(preset_name)
        if not profile:
            return None

        return generate_guide(entry, profile)

    def analyze_target(self, user_text: str) -> Dict[str, Any]:
        """Parse a user's description into a structured target profile.

        Args:
            user_text: Natural language target description

        Returns:
            Structured target profile dictionary
        """
        return parse_user_profile(user_text)

    def get_exploits_for_target(self, target_os: str, target_arch: str = "",
                                category: str = "") -> List[Dict[str, Any]]:
        """Find all exploits that could work against a target.

        Args:
            target_os: Target OS
            target_arch: Target architecture
            category: Optional device category (router, browser, etc.)

        Returns:
            List of exploit summaries with scores
        """
        ranker = ExploitRanker(target_os=target_os, target_arch=target_arch,
                               target_category=category)
        if category == "router":
            entries = ranker.find_by_category("router")
        else:
            entries = None
        ranked, _ = ranker.rank(entries=entries, top_n=20)

        results = []
        for entry, score, breakdown in ranked:
            msf = entry.trigger_primitives.custom.get("metasploit_module", "")
            results.append({
                "cve_id": entry.cve_id,
                "vuln_type": entry.vulnerability_type,
                "score": score,
                "metasploit_module": msf,
                "platform": entry.target,
                "description": entry.description[:200],
            })
        return results

    def compare_exploits(self, cve_ids: List[str], target_profile: Dict[str, Any] = None) -> str:
        """Compare multiple exploits and recommend the best one.

        Args:
            cve_ids: List of CVE IDs to compare
            target_profile: Optional target profile for scoring

        Returns:
            Comparison table with recommendations
        """
        entries = []
        for cve_id in cve_ids:
            entry = lookup_cve(cve_id)
            if entry:
                entries.append(entry)

        if not entries:
            return "No valid CVEs found for comparison."

        # Rank them
        if target_profile:
            ranker = ExploitRanker(
                target_os=target_profile.get("os", ""),
                target_arch=target_profile.get("arch", ""),
                target_mitigations=target_profile.get("mitigations", {})
            )
        else:
            ranker = ExploitRanker()

        ranked, _ = ranker.rank(entries=entries, top_n=len(entries))

        lines = ["## Exploit Comparison\n"]
        for i, (entry, score, breakdown) in enumerate(ranked, 1):
            msf = entry.trigger_primitives.custom.get("metasploit_module", "")
            msf_tag = f"\n  Metasploit: `{msf}`" if msf else ""

            lines.append(f"### {i}. {entry.cve_id} — Score: {score}/100")
            lines.append(f"- **Type:** {entry.vulnerability_type}")
            lines.append(f"- **Target:** {entry.target}")
            lines.append(f"- **Severity:** {entry.severity}")
            lines.append(f"- **Description:** {entry.description[:150]}...{msf_tag}")

            # Score breakdown
            scores_str = " | ".join(f"{k}: {v:.0f}" for k, v in breakdown.items())
            lines.append(f"- **Scores:** {scores_str}")
            lines.append("")

        # Recommendation
        if ranked:
            best = ranked[0]
            lines.append(f"## Recommendation\n")
            lines.append(f"**Best choice: {best[0].cve_id}** (score {best[1]}/100)\n")
            lines.append(f"Reason: Highest score across platform match, severity, "
                        f"Metasploit availability, and active exploitation status.\n")

        return "\n".join(lines)

    def ask_target_questions(self) -> str:
        """Generate the target profiling questions for Jarvis to ask.

        Returns:
            Formatted questions for Jarvis to present to the user
        """
        questions = get_profile_questions()
        lines = ["## Target Information Needed\n"]
        lines.append("To recommend the best exploit, I need to know about your target:\n")

        for q in questions:
            lines.append(f"**{q['question']}**")
            if "options" in q:
                lines.append(f"Options: {', '.join(q['options'])}")
            if "placeholder" in q:
                lines.append(f"Example: {q['placeholder']}")
            lines.append("")

        lines.append("Available preset profiles (type name to use):")
        lines.append(list_presets())

        return "\n".join(lines)


def process_cve_query(query: str) -> Optional[str]:
    """Main interface for Jarvis to process CVE-related queries.

    This is the single entry point that:
    1. Looks up the CVE in the knowledge base
    2. If found, generates the PoC code directly from templates
    3. Returns the code (bypassing LLM text generation for binary data)

    Args:
        query: CVE ID or keyword search

    Returns:
        Complete Python PoC code, or None if not found
    """
    bridge = SecurityBridge()
    return bridge.generate_poc(query)


def get_context_for_llm(query: str) -> Optional[str]:
    """Get vulnerability context for LLM to discuss (without generating code).

    Args:
        query: CVE ID or keyword search

    Returns:
        Formatted vulnerability information
    """
    bridge = SecurityBridge()
    return bridge.get_vulnerability_info(query)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python bridge.py <CVE-ID>                      # Generate PoC code")
        print("  python bridge.py info <CVE-ID>                 # Show vulnerability info")
        print("  python bridge.py list [keyword]                # List database entries")
        print("  python bridge.py ingest                        # Run ingestion engine")
        print("  python bridge.py rank <platform> [arch]        # Rank exploits for target")
        print("  python bridge.py guide <CVE-ID> <preset>       # Adaptation guide")
        print("  python bridge.py compare <CVE1> <CVE2> ...     # Compare exploits")
        print("  python bridge.py profile                       # Show target profiling questions")
        print("  python bridge.py presets                       # List preset profiles")
        sys.exit(1)

    bridge = SecurityBridge()

    if sys.argv[1] == "ingest":
        count = bridge.ingest()
        print(f"Database contains {count} entries")

    elif sys.argv[1] == "list":
        keyword = sys.argv[2] if len(sys.argv) > 2 else None
        entries = bridge.list_vulnerabilities(keyword)
        for e in entries:
            print(f"{e['cve_id']} [{e['type']}] -> {e['target']}")

    elif sys.argv[1] == "info":
        if len(sys.argv) < 3:
            print("Usage: python bridge.py info <CVE-ID>")
            sys.exit(1)
        info = bridge.get_vulnerability_info(sys.argv[2])
        if info:
            print(info)
        else:
            print(f"Vulnerability {sys.argv[2]} not found")

    elif sys.argv[1] == "rank":
        platform = sys.argv[2] if len(sys.argv) > 2 else ""
        arch = sys.argv[3] if len(sys.argv) > 3 else ""
        print(bridge.rank_exploits_for_target(platform, arch))

    elif sys.argv[1] == "guide":
        if len(sys.argv) < 4:
            print("Usage: python bridge.py guide <CVE-ID> <preset_profile>")
            print("Presets: android_modern, android_old, linux_server, linux_embedded, windows_11, windows_server")
            sys.exit(1)
        guide = bridge.get_guide_for_preset(sys.argv[2], sys.argv[3])
        if guide:
            print(guide)
        else:
            print(f"Could not generate guide for {sys.argv[2]} with profile {sys.argv[3]}")

    elif sys.argv[1] == "compare":
        if len(sys.argv) < 4:
            print("Usage: python bridge.py compare <CVE1> <CVE2> ...")
            sys.exit(1)
        print(bridge.compare_exploits(sys.argv[2:]))

    elif sys.argv[1] == "profile":
        print(bridge.ask_target_questions())

    elif sys.argv[1] == "presets":
        print(list_presets())

    else:
        code = bridge.generate_poc(sys.argv[1])
        if code:
            print(code)
        else:
            print(f"Vulnerability {sys.argv[1]} not found. Try 'ingest' first.")
