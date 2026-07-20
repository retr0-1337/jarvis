#!/usr/bin/env python3
"""NVD (National Vulnerability Database) API integration.

Queries CVEs by CPE string or keyword search. Caches results locally.
Rate-limited to 5 requests/30s without API key, 50/30s with key.
"""

import json
import os
import re
import time
import urllib.request
import urllib.parse
import urllib.error

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.expanduser("~/.local/share/jarvis/nvd_cache")
CACHE_TTL = 86400 * 7  # 7 days


def _cache_path(key: str) -> str:
    safe = re.sub(r'[^\w\-]', '_', key)[:120]
    return os.path.join(CACHE_DIR, f"{safe}.json")


def _load_cache(key: str):
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        if time.time() - data.get("ts", 0) > CACHE_TTL:
            return None
        return data.get("results")
    except Exception:
        return None


def _save_cache(key: str, results):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = _cache_path(key)
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "results": results}, f)
    except Exception:
        pass


def query_cves(cpe_name: str = "", keyword: str = "", max_results: int = 20) -> list:
    """Query NVD for CVEs. Returns list of dicts with:
    cve_id, description, severity, cvss, published, references
    """
    cache_key = f"cpe:{cpe_name}|kw:{keyword}"
    cached = _load_cache(cache_key)
    if cached is not None:
        return cached

    params = {"resultsPerPage": min(max_results, 200)}
    if cpe_name:
        params["cpeName"] = cpe_name
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []

    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Jarvis-Pentest/1.0",
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[NVD] API error: {e}", flush=True)
        return []
    except Exception as e:
        print(f"[NVD] Unexpected error: {e}", flush=True)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "unknown"
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown")
                break

        refs = []
        for r in cve.get("references", []):
            refs.append(r.get("url", ""))

        published = cve.get("published", "")[:10]

        # Check for known exploits in references
        has_exploit = any(
            "exploit" in r.lower() or "github.com" in r.lower() or "packetstorm" in r.lower()
            for r in refs
        )

        # Check for Metasploit module references
        msf_module = ""
        for r in refs:
            url = r.get("url", "") if isinstance(r, dict) else r
            if "metasploit" in url.lower() or "rapid7" in url.lower():
                msf_module = url
                break

        results.append({
            "cve_id": cve_id,
            "description": desc[:500],
            "severity": severity,
            "cvss": cvss_score,
            "published": published,
            "references": refs[:10],
            "has_exploit": has_exploit,
            "msf_reference": msf_module,
        })

    _save_cache(cache_key, results)
    return results


def lookup_cve(cve_id: str) -> dict:
    """Look up a single CVE by ID. Returns dict or empty dict."""
    cache_key = f"cve:{cve_id}"
    cached = _load_cache(cache_key)
    if cached is not None and cached:
        return cached[0]

    url = f"{NVD_API}?cveId={urllib.parse.quote(cve_id)}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Jarvis-Pentest/1.0",
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"[NVD] Lookup error for {cve_id}: {e}", flush=True)
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}

    results = query_cves(cpe_name="", keyword=cve_id, max_results=1)
    if results:
        _save_cache(cache_key, results)
        return results[0]
    return {}


def cpe_for_service(service: str, product: str = "", version: str = "") -> str:
    """Build a CPE 2.3 string for a service."""
    parts = ["cpe:2.3:a"]
    parts.append("*" if not product else re.sub(r'[^a-z0-9]', '_', product.lower()))
    parts.append("*" if not version else re.sub(r'[^a-z0-9._-]', '_', version))
    return ":".join(parts) + ":*"


def enrich_with_nvd(discovered: dict, raw_nmap: str = "") -> dict:
    """Enrich exploit discovery results with NVD CVE data.

    For each service found in discovered, queries NVD for additional CVEs
    and merges them into the results. Returns enriched discovered dict.
    """
    from exploit_discovery import _identify_router_model

    vendor, model = _identify_router_model(raw_nmap) if raw_nmap else ("", "")

    enriched = dict(discovered)
    queried = set()

    for port, exploits in discovered.items():
        for exp in exploits:
            svc = exp.get("service", "")
            product = exp.get("product", "")

            if product and product not in queried:
                queried.add(product)
                cpe = cpe_for_service(svc, product)
                nvd_cves = query_cves(cpe_name=cpe, max_results=10)

                existing_ids = {e.get("cve_id", "") for e in exploits}
                for nvd in nvd_cves:
                    if nvd["cve_id"] not in existing_ids and nvd["cvss"] >= 5.0:
                        enriched.setdefault(port, []).append({
                            "cve_id": nvd["cve_id"],
                            "type": "nvd_lookup",
                            "severity": nvd["severity"].lower(),
                            "score": nvd["cvss"],
                            "description": nvd["description"][:200],
                            "metasploit_module": "",
                            "source": "nvd",
                            "service": svc,
                            "has_exploit": nvd.get("has_exploit", False),
                        })

    if vendor and vendor not in queried:
        queried.add(vendor)
        keyword = f"{vendor} {model}" if model else vendor
        nvd_cves = query_cves(keyword=keyword, max_results=10)
        all_existing = set()
        for port, exps in enriched.items():
            for e in exps:
                all_existing.add(e.get("cve_id", ""))

        for nvd in nvd_cves:
            if nvd["cve_id"] not in all_existing and nvd["cvss"] >= 4.0:
                target_port = list(enriched.keys())[0] if enriched else "unknown"
                enriched.setdefault(target_port, []).append({
                    "cve_id": nvd["cve_id"],
                    "type": "nvd_vendor_lookup",
                    "severity": nvd["severity"].lower(),
                    "score": nvd["cvss"],
                    "description": nvd["description"][:200],
                    "metasploit_module": "",
                    "source": "nvd",
                    "service": f"{vendor} router",
                    "has_exploit": nvd.get("has_exploit", False),
                })

    return enriched


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.startswith("CVE-"):
            result = lookup_cve(arg)
            print(json.dumps(result, indent=2))
        else:
            results = query_cves(keyword=arg)
            for r in results[:5]:
                print(f"{r['cve_id']} [{r['severity']} {r['cvss']}] {r['description'][:100]}")
    else:
        print("Usage: python3 nvd_api.py <CVE-ID or keyword>")
