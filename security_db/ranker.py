"""Exploit ranking system for Jarvis.

Scores and ranks exploits based on platform match, architecture,
severity, Metasploit availability, and active exploitation status.
"""
import os
import sys
from typing import Dict, List, Optional, Any, Tuple

sys.path.insert(0, os.path.dirname(__file__))
from schema import load_database, VulnerabilityEntry


# Weight factors for scoring
WEIGHTS = {
    "platform": 30,           # Does exploit match target platform?
    "arch": 20,               # Does exploit match target architecture?
    "severity": 15,            # CVSS severity score
    "metasploit": 15,          # Is there a verified Metasploit module?
    "actively_exploited": 10,  # Is it in CISA KEV (actively exploited)?
    "patch_status": 10,        # Is the target likely unpatched?
}

# Platform mapping from OS names to exploit platform tags
PLATFORM_MAP = {
    "android": ["android", "linux"],
    "linux": ["linux", "unix"],
    "windows": ["windows", "win"],
    "macos": ["osx", "apple"],
    "ios": ["apple_ios", "ios"],
    "chromeos": ["linux"],
    "freebsd": ["freebsd", "bsd"],
    "openbsd": ["openbsd", "bsd"],
}

# Router/network device keywords — MSF module paths use vendor names directly
ROUTER_KEYWORDS = [
    "netgear", "linksys", "dlink", "d-link", "tp-link", "tplink",
    "asuswrt", "asus_r", "mikrotik", "ubiquiti", "ubnt",
    "openwrt", "ddwrt", "dd-wrt",
    "fortigate", "fortigateway", "fortios",
    "sophos_utm", "sophos_webadmin",
    "paloalto", "palo_alto", "pan-os", "panos",
    "juniper", "aruba",
    "sonicwall", "sonicwall_gms",
    "zyxel", "davolink", "netis", "tenda", "comtrend",
    "firepower", "cisco_rv", "cisco_ios_xe",
]

# Architecture mapping
ARCH_MAP = {
    "arm64": ["ARCH_ARM64", "aarch64", "arm"],
    "arm": ["ARCH_ARMLE", "arm", "armv7", "armv8"],
    "x86_64": ["ARCH_X86", "x86_64", "x64"],
    "x86": ["ARCH_X86", "x86", "i386"],
    "mips": ["ARCH_MIPSLE", "mips"],
    "riscv": ["ARCH_RISCV", "riscv"],
}

# Severity scoring
SEVERITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "unknown": 30,
}

# CISA KEV = actively exploited = higher confidence
KEV_BONUS = 25


class ExploitRanker:
    """Rank exploits based on multiple factors."""

    def __init__(self, target_os: str = "", target_arch: str = "",
                 target_mitigations: Optional[Dict[str, bool]] = None,
                 target_category: str = ""):
        self.target_os = target_os.lower()
        self.target_arch = target_arch.lower()
        self.target_mitigations = target_mitigations or {}
        self.target_category = target_category.lower()
        self.database = load_database()

    def _is_router_exploit(self, entry: VulnerabilityEntry) -> bool:
        """Check if an exploit targets a router/network device."""
        msf_path = entry.trigger_primitives.custom.get("metasploit_module", "").lower()
        desc = entry.description.lower()
        # MSF module path is the strongest signal — vendor name in path = router exploit
        if msf_path and any(kw in msf_path for kw in ROUTER_KEYWORDS):
            return True
        # For non-MSF entries, check if description explicitly mentions router/network device
        if not msf_path:
            router_desc_kw = ["router", "routers", "network device", "firewall", "access point"]
            if any(kw in desc for kw in router_desc_kw):
                return True
        return False

    def _score_platform(self, entry: VulnerabilityEntry) -> float:
        """Score how well exploit matches target platform."""
        if not self.target_os:
            return 50.0  # Neutral if no target specified

        entry_platform = entry.target.lower()
        entry_desc = entry.description.lower()

        # Direct platform match (e.g. "android" entry for "android" target)
        if self.target_os in entry_platform:
            return 100.0

        # Parent platform: e.g. "linux" entry for "android" target (Android runs Linux kernel)
        if self.target_os in PLATFORM_MAP:
            for plat in PLATFORM_MAP[self.target_os]:
                if plat == self.target_os:
                    continue
                if plat in entry_platform:
                    # For android target: only local/kernel linux exploits are relevant
                    msf_path = entry.trigger_primitives.custom.get("metasploit_module", "")
                    if self.target_os == "android" and "linux" in plat:
                        if "/local/" in msf_path:
                            return 90.0  # Kernel/local exploit — relevant to Android
                        return 5.0  # Remote service exploit — NOT Android-relevant
                    return 80.0

        # Cross-platform exploits
        if "multi" in entry_platform or "cross-platform" in entry_desc:
            return 50.0

        # Penalize clearly unrelated platforms
        UNRELATED = {"android": ["java", "php", "python", "ruby", "node",
                                 "cisco", "windows", "macos", "solaris",
                                 "oracle", "tomcat", "iis"]}
        if self.target_os in UNRELATED:
            for unrelated in UNRELATED[self.target_os]:
                if unrelated in entry_platform:
                    return 10.0

        # Partial keyword match in description
        if self.target_os in entry_desc:
            return 40.0

        return 20.0

    def _score_arch(self, entry: VulnerabilityEntry) -> float:
        """Score how well exploit matches target architecture."""
        if not self.target_arch:
            return 50.0

        entry_target = entry.target.lower()
        entry_desc = entry.description.lower()

        for arch_key, arch_tags in ARCH_MAP.items():
            if arch_key in self.target_arch:
                for tag in arch_tags:
                    if tag.lower() in entry_target or tag.lower() in entry_desc:
                        return 100.0

        # Architecture-agnostic exploits (e.g., format string, logic bugs)
        if any(kw in entry_desc for kw in ["logic", "race", "format string", "type confusion"]):
            return 80.0

        return 30.0

    def _score_severity(self, entry: VulnerabilityEntry) -> float:
        """Score based on severity."""
        return SEVERITY_SCORES.get(entry.severity.lower(), 30.0)

    def _score_metasploit(self, entry: VulnerabilityEntry) -> float:
        """Score based on Metasploit module availability."""
        msf_module = entry.trigger_primitives.custom.get("metasploit_module", "")
        msf_name = entry.trigger_primitives.custom.get("msf_name", "")

        if msf_module:
            return 100.0
        if msf_name:
            return 90.0

        # Check if there's likely a Metasploit module (based on naming)
        if "exploit" in entry.cve_id.lower():
            return 50.0

        return 20.0

    def _score_actively_exploited(self, entry: VulnerabilityEntry) -> float:
        """Score based on active exploitation status (CISA KEV)."""
        # If it's in the database from CISA KEV ingestion, it's confirmed exploited
        # Check for KEV indicators in references
        for ref in entry.references:
            if "cisa" in ref.lower() or "kev" in ref.lower():
                return 100.0

        # If it has Metasploit module, it's likely verified
        if entry.trigger_primitives.custom.get("metasploit_module"):
            return 80.0

        return 30.0

    def _score_patch_status(self, entry: VulnerabilityEntry) -> float:
        """Score based on likely patch status."""
        if not self.target_os:
            return 50.0

        # Older CVEs are more likely patched on modern systems
        try:
            year = int(entry.cve_id.split("-")[1])
            if year < 2020:
                return 30.0  # Likely patched
            elif year < 2023:
                return 60.0  # Might be patched
            else:
                return 90.0  # Likely unpatched
        except (IndexError, ValueError):
            return 50.0

    def _score_mitigations(self, entry: VulnerabilityEntry) -> float:
        """Score based on mitigation effectiveness."""
        if not self.target_mitigations:
            return 50.0

        # If target has strong mitigations, score lower for exploits that
        # rely on disabled mitigations
        vtype = entry.vulnerability_type.lower()

        if vtype == "buffer_overflow":
            if self.target_mitigations.get("aslr") and self.target_mitigations.get("dep"):
                return 40.0  # Harder with full mitigations
            elif self.target_mitigations.get("aslr"):
                return 60.0
            return 80.0

        if vtype == "use_after_free":
            if self.target_mitigations.get("cfi"):
                return 30.0  # CFI blocks most UAF
            return 70.0

        if vtype == "kernel_memory":
            if self.target_mitigations.get("selinux") or self.target_mitigations.get("kptr_restrict"):
                return 40.0  # Stronger kernel hardening
            return 70.0

        return 50.0

    def rank(self, entries: Optional[List[VulnerabilityEntry]] = None,
             top_n: int = 10) -> List[Tuple[VulnerabilityEntry, float, Dict[str, float]]]:
        """Rank exploits and return top N.

        Returns:
            List of (entry, total_score, score_breakdown) tuples, sorted by score
        """
        if entries is None:
            entries = self.database

        scored = []
        for entry in entries:
            scores = {
                "platform": self._score_platform(entry),
                "arch": self._score_arch(entry),
                "severity": self._score_severity(entry),
                "metasploit": self._score_metasploit(entry),
                "actively_exploited": self._score_actively_exploited(entry),
                "patch_status": self._score_patch_status(entry),
            }

            # Add mitigation score if target specified
            if self.target_mitigations:
                scores["mitigations"] = self._score_mitigations(entry)

            # Weighted total
            total = 0.0
            weight_sum = 0.0
            for key, score in scores.items():
                weight = WEIGHTS.get(key, 10)
                total += score * (weight / 100.0)
                weight_sum += weight

            # Normalize to 0-100
            if weight_sum > 0:
                total = (total / weight_sum) * 100.0

            scored.append((entry, round(total, 1), scores))

        # Sort by total score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n], len(scored)

    def find_by_platform(self, platform: str) -> List[VulnerabilityEntry]:
        """Find all exploits for a specific platform."""
        results = []
        for entry in self.database:
            entry_platform = entry.target.lower()
            entry_desc = entry.description.lower()

            for target_key, platforms in PLATFORM_MAP.items():
                if target_key in platform.lower():
                    for plat in platforms:
                        if plat in entry_platform or plat in entry_desc:
                            results.append(entry)
                            break

        return results

    def find_by_category(self, category: str) -> List[VulnerabilityEntry]:
        """Find all exploits for a specific device category (router, browser, etc.)."""
        results = []
        for entry in self.database:
            if category == "router" and self._is_router_exploit(entry):
                results.append(entry)
        return results

    def find_by_type(self, vuln_type: str) -> List[VulnerabilityEntry]:
        """Find exploits by vulnerability type."""
        return [e for e in self.database
                if vuln_type.lower() in e.vulnerability_type.lower()]

    def get_metasploit_modules(self, entries: List[VulnerabilityEntry]) -> List[Dict[str, str]]:
        """Get Metasploit module info for entries."""
        modules = []
        for entry in entries:
            msf_module = entry.trigger_primitives.custom.get("metasploit_module", "")
            msf_name = entry.trigger_primitives.custom.get("msf_name", "")
            if msf_module or msf_name:
                modules.append({
                    "cve_id": entry.cve_id,
                    "module_path": msf_module,
                    "module_name": msf_name,
                    "vuln_type": entry.vulnerability_type,
                    "platform": entry.target,
                })
        return modules


def rank_exploits(target_os: str = "", target_arch: str = "",
                  vuln_type: str = "", category: str = "",
                  top_n: int = 5) -> str:
    """High-level function to rank exploits and format results.

    Returns formatted string with ranked exploits and scores.
    """
    ranker = ExploitRanker(target_os=target_os, target_arch=target_arch,
                           target_category=category)

    entries = None
    if category == "router":
        entries = ranker.find_by_category("router")
    elif vuln_type:
        entries = ranker.find_by_type(vuln_type)

    ranked, total_available = ranker.rank(entries=entries, top_n=top_n)

    if not ranked:
        return "No exploits found matching your criteria."

    h = []
    h.append('<div class="exploit-rank-header">')
    if top_n >= total_available:
        h.append(f'<h2>All {total_available} Exploits</h2>')
    else:
        h.append(f'<h2>Exploit Rankings <span class="rank-count">Top {len(ranked)} of {total_available} available</span></h2>')
    h.append(f'<div class="rank-target">Target: <strong>{target_os or "any"}</strong>{f" / <strong>{target_arch}</strong>" if target_arch and target_arch != "unknown" else ""}</div>')
    h.append('</div>')

    for i, (entry, score, breakdown) in enumerate(ranked, 1):
        msf = entry.trigger_primitives.custom.get("metasploit_module", "")
        score_class = "high" if score >= 70 else ("medium" if score >= 40 else "low")

        h.append('<div class="exploit-card">')
        h.append('<div class="exploit-card-head">')
        h.append(f'<span class="exploit-rank">#{i}</span>')
        h.append(f'<span class="exploit-cve">{entry.cve_id}</span>')
        h.append(f'<span class="exploit-score {score_class}">{score:.1f}</span>')
        h.append('</div>')
        h.append('<div class="exploit-card-body">')
        h.append(f'<div class="exploit-meta"><span class="exploit-type">{entry.vulnerability_type}</span><span class="exploit-severity sev-{entry.severity}">{entry.severity}</span><span class="exploit-target">{entry.target}</span></div>')

        if msf:
            h.append(f'<div class="exploit-msf"><span class="msf-label">Metasploit</span><code>{msf}</code></div>')

        h.append(f'<div class="exploit-desc">{entry.description[:200]}...</div>')

        h.append('<div class="exploit-scores">')
        for k, v in breakdown.items():
            bar_w = int(v)
            h.append(f'<div class="score-bar-row"><span class="score-label">{k}</span><div class="score-bar-bg"><div class="score-bar-fill {score_class}" style="width:{bar_w}%"></div></div><span class="score-val">{v:.0f}</span></div>')
        h.append('</div>')
        h.append(f'<!--POC:{entry.cve_id}-->')
        h.append('</div></div>')

    # Build TTS summary — cap spoken list at 10 even if showing more
    tts_count = min(len(ranked), 10)
    if top_n >= total_available:
        tts_parts = [f"All {total_available} exploits for {target_os or 'any'}{', ' + target_arch if target_arch and target_arch != 'unknown' else ''}."]
    else:
        tts_parts = [f"Found {total_available} exploits for {target_os or 'any'}{', ' + target_arch if target_arch and target_arch != 'unknown' else ''}. Showing top {len(ranked)}."]
    for i, (entry, score, _) in enumerate(ranked[:tts_count], 1):
        msf = entry.trigger_primitives.custom.get("metasploit_module", "")
        msf_text = f" Metasploit module: {msf}." if msf else ""
        tts_parts.append(f"Number {i}: {entry.cve_id}, score {score}. {entry.vulnerability_type}. {entry.target}.{msf_text}")
    tts_summary = " ".join(tts_parts)

    return f'<!--EXPLOIT_START--><!--TTS:{tts_summary}-->' + '\n'.join(h) + '<!--EXPLOIT_END-->'


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ranker.py <platform> [arch] [vuln_type]")
        print("Example: python ranker.py android arm64")
        print("Example: python ranker.py windows x86_64 buffer_overflow")
        sys.exit(1)

    platform = sys.argv[1] if len(sys.argv) > 1 else ""
    arch = sys.argv[2] if len(sys.argv) > 2 else ""
    vtype = sys.argv[3] if len(sys.argv) > 3 else ""

    print(rank_exploits(target_os=platform, target_arch=arch, vuln_type=vtype))
