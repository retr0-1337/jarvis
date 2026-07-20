"""Target profiler for Jarvis.

Collects target environment details through structured questions,
enabling the ranker and guide to provide targeted recommendations.
"""
import json
import os
import sys
from typing import Dict, Optional, Any

sys.path.insert(0, os.path.dirname(__file__))

PROFILE_DIR = os.path.join(os.path.dirname(__file__), "profiles")
os.makedirs(PROFILE_DIR, exist_ok=True)


# Predefined target profiles for quick selection
PRESET_PROFILES = {
    "android_modern": {
        "os": "android",
        "version": "14",
        "arch": "arm64",
        "mitigations": {
            "aslr": True,
            "dep": True,
            "pie": True,
            "pac": True,     # Pointer Authentication (ARMv8.3+)
            "mte": False,    # Memory Tagging (Android 12+ optional)
            "selinux": True,
        },
        "description": "Modern Android device (Pixel, Samsung flagship)"
    },
    "android_old": {
        "os": "android",
        "version": "7-9",
        "arch": "arm",
        "mitigations": {
            "aslr": True,
            "dep": True,
            "pie": True,
            "pac": False,
            "selinux": True,
        },
        "description": "Older Android device (2017-2019 era)"
    },
    "linux_server": {
        "os": "linux",
        "version": "ubuntu 22.04",
        "arch": "x86_64",
        "mitigations": {
            "aslr": True,
            "dep": True,
            "pie": True,
            "stack_canary": True,
            "kptr_restrict": True,
            "selinux": False,
        },
        "description": "Standard Linux server (Ubuntu/Debian)"
    },
    "linux_embedded": {
        "os": "linux",
        "version": "busybox",
        "arch": "arm",
        "mitigations": {
            "aslr": False,
            "dep": True,
            "pie": False,
            "stack_canary": False,
            "kptr_restrict": False,
        },
        "description": "Embedded Linux (IoT, router, camera)"
    },
    "windows_11": {
        "os": "windows",
        "version": "11",
        "arch": "x86_64",
        "mitigations": {
            "aslr": True,
            "dep": True,
            "cfg": True,     # Control Flow Guard
            "cet": True,     # Control-flow Enforcement Technology
            "acg": True,     # Arbitrary Code Guard
            "hwaci": True,   # Hardware-enforced Stack Protection
        },
        "description": "Windows 11 with full mitigations"
    },
    "windows_server": {
        "os": "windows",
        "version": "server 2022",
        "arch": "x86_64",
        "mitigations": {
            "aslr": True,
            "dep": True,
            "cfg": True,
            "cet": True,
        },
        "description": "Windows Server 2022"
    },
}


def get_profile_questions() -> list:
    """Return structured questions for target profiling."""
    return [
        {
            "id": "os",
            "question": "What is the target operating system?",
            "options": ["android", "linux", "windows", "macos", "ios", "other"],
            "required": True,
        },
        {
            "id": "version",
            "question": "What is the OS version or distribution?",
            "placeholder": "e.g., 'android 14', 'ubuntu 22.04', 'windows 11'",
            "required": True,
        },
        {
            "id": "arch",
            "question": "What is the target architecture?",
            "options": ["arm64", "arm", "x86_64", "x86", "mips", "riscv"],
            "required": True,
        },
        {
            "id": "access",
            "question": "What is your current access level?",
            "options": [
                "unauthenticated (remote)",
                "authenticated user",
                "local user (no root)",
                "local user (root/admin)",
            ],
            "required": True,
        },
        {
            "id": "goal",
            "question": "What is your exploitation goal?",
            "options": [
                "remote code execution",
                "local privilege escalation",
                "sandbox escape",
                "information leak",
                "denial of service",
            ],
            "required": True,
        },
    ]


def get_mitigations_for_profile(profile: Dict[str, Any]) -> Dict[str, bool]:
    """Get likely mitigations based on OS and version."""
    os_name = profile.get("os", "").lower()
    version = profile.get("version", "").lower()

    # Start with defaults
    mitigations = {
        "aslr": True,
        "dep": True,
        "pie": True,
        "stack_canary": True,
    }

    if os_name == "android":
        # Android has strong mitigations
        mitigations.update({
            "selinux": True,
            "pac": True if any(v in version for v in ["12", "13", "14", "15"]) else False,
            "mte": True if "14" in version else False,
        })
        if any(v in version for v in ["7", "8", "9"]):
            mitigations["pac"] = False
            mitigations["mte"] = False

    elif os_name == "linux":
        mitigations.update({
            "kptr_restrict": True,
            "ptrace_scope": True,
            "selinux": False,
        })
        # Embedded/IoT often has weak mitigations
        if any(kw in version for kw in ["busybox", "openwrt", "embedded", "iot"]):
            mitigations.update({
                "aslr": False,
                "pie": False,
                "stack_canary": False,
                "kptr_restrict": False,
            })

    elif os_name == "windows":
        mitigations.update({
            "cfg": True,     # Control Flow Guard
            "acg": True,     # Arbitrary Code Guard
            "hwaci": True,   # Hardware-enforced Stack Protection
        })
        if any(v in version for v in ["11", "server 2022", "10 22h2"]):
            mitigations["cet"] = True  # Control-flow Enforcement

    elif os_name == "macos":
        mitigations.update({
            "sip": True,     # System Integrity Protection
            "amfi": True,    # Apple Mobile File Integrity
            "pac": True,     # Pointer Authentication (M1+)
        })

    return mitigations


def format_profile(profile: Dict[str, Any]) -> str:
    """Format a profile for display."""
    lines = ["## Target Profile\n"]
    lines.append(f"- **OS:** {profile.get('os', 'unknown')}")
    lines.append(f"- **Version:** {profile.get('version', 'unknown')}")
    lines.append(f"- **Architecture:** {profile.get('arch', 'unknown')}")
    lines.append(f"- **Access:** {profile.get('access', 'unknown')}")
    lines.append(f"- **Goal:** {profile.get('goal', 'unknown')}")

    mit = profile.get("mitigations", {})
    if mit:
        enabled = [k for k, v in mit.items() if v]
        disabled = [k for k, v in mit.items() if not v]
        lines.append(f"- **Mitigations enabled:** {', '.join(enabled) or 'none'}")
        lines.append(f"- **Mitigations disabled:** {', '.join(disabled) or 'none'}")

    return "\n".join(lines)


def save_profile(name: str, profile: Dict[str, Any]):
    """Save a profile for reuse."""
    path = os.path.join(PROFILE_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)


def load_profile(name: str) -> Optional[Dict[str, Any]]:
    """Load a saved profile."""
    path = os.path.join(PROFILE_DIR, f"{name}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def list_presets() -> str:
    """List available preset profiles."""
    lines = ["## Available Target Presets\n"]
    for name, profile in PRESET_PROFILES.items():
        lines.append(f"- **{name}**: {profile['description']}")
        lines.append(f"  - OS: {profile['os']}, Arch: {profile['arch']}, Version: {profile['version']}")
    return "\n".join(lines)


def parse_user_profile(user_text: str) -> Dict[str, Any]:
    """Parse a user's free-text description into a structured profile.

    This is the smart parser that extracts OS, version, arch from natural language.
    """
    text = user_text.lower()
    profile = {
        "os": "unknown",
        "version": "unknown",
        "arch": "unknown",
        "mitigations": {},
    }

    # Detect OS
    if "android" in text:
        profile["os"] = "android"
    elif any(kw in text for kw in ["linux", "ubuntu", "debian", "centos", "fedora", "arch linux"]):
        profile["os"] = "linux"
    elif any(kw in text for kw in ["router", "routers", "network", "iot", "embedded", "camera", "firewall"]):
        profile["os"] = "linux"
        profile["version"] = "embedded"
    elif "windows" in text or "win" in text:
        profile["os"] = "windows"
    elif "macos" in text or "mac os" in text or "osx" in text:
        profile["os"] = "macos"
    elif "ios" in text:
        profile["os"] = "ios"

    # Detect version
    import re
    version_match = re.search(r'(?:version|v\.?|ver\.?)\s*(\d+[\.\d]*)', text)
    if version_match:
        profile["version"] = version_match.group(1)
    else:
        # Try common patterns
        for pattern in [r'android\s*(\d+)', r'ubuntu\s*([\d.]+)', r'windows\s*(\d+)',
                        r'(\d+\.?\d*)', r'(\d+)(?:st|nd|rd|th)']:
            m = re.search(pattern, text)
            if m:
                profile["version"] = m.group(1)
                break

    # Detect architecture
    if any(kw in text for kw in ["aarch64", "arm64", "armv8"]):
        profile["arch"] = "arm64"
    elif any(kw in text for kw in ["armv7", "armhf", "arm "]):
        profile["arch"] = "arm"
    elif any(kw in text for kw in ["x86_64", "x64", "amd64"]):
        profile["arch"] = "x86_64"
    elif any(kw in text for kw in ["x86", "i386", "i686"]):
        profile["arch"] = "x86"
    elif "mips" in text:
        profile["arch"] = "mips"
    elif "riscv" in text or "risc-v" in text:
        profile["arch"] = "riscv"

    # Get mitigations
    profile["mitigations"] = get_mitigations_for_profile(profile)

    return profile


if __name__ == "__main__":
    print(list_presets())
