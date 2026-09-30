"""
Nine threat intelligence provider adapters for PRAMAAN.

Each provider:
  - takes an indicator (IP/domain/URL)
  - returns a dict with at least {"malicious": bool, ...}
  - respects a 4-second timeout
  - never raises on failure (returns {} on error)
"""
import asyncio
import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx
import dns.resolver
import dns.reversename

TIMEOUT_SECONDS = 4.0


# ── Helper ──────────────────────────────────────────────────

async def _safe_get_json(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
) -> Optional[Dict]:
    """GET a URL and return JSON; None on any failure."""
    try:
        r = await client.get(url, headers=headers, params=params, timeout=TIMEOUT_SECONDS)
        if r.status_code == 200:
            return r.json()
        return {"_http_status": r.status_code}
    except Exception as e:
        return {"_error": str(e)}


def _has_key(name: str) -> bool:
    return bool(os.getenv(name))


# ── 1. VirusTotal v3 ─────────────────────────────────────────

async def virustotal(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"_unavailable": "no VIRUSTOTAL_API_KEY"}

    # Detect which VT endpoint to hit
    if _looks_like_ip(indicator):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"

    data = await _safe_get_json(client, url, headers={"x-apikey": api_key})
    if not data or "_error" in data or "_http_status" in data:
        return {}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    return {
        "malicious": malicious > 0,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "reputation": attrs.get("reputation", 0),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
    }


# ── 2. AbuseIPDB v2 ──────────────────────────────────────────

async def abuseipdb(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"_unavailable": "no ABUSEIPDB_API_KEY"}
    if not _looks_like_ip(indicator):
        return {"_skipped": "only supports IPs"}

    data = await _safe_get_json(
        client,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": indicator, "maxAgeInDays": 90},
    )
    if not data or "_error" in data or "_http_status" in data:
        return {}

    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    return {
        "malicious": score >= 25,
        "abuse_score": score,
        "total_reports": d.get("totalReports", 0),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "usage_type": d.get("usageType"),
    }


# ── 3. IPinfo ────────────────────────────────────────────────

async def ipinfo(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    token = os.getenv("IPINFO_TOKEN")
    if not token:
        return {"_unavailable": "no IPINFO_TOKEN"}

    data = await _safe_get_json(
        client,
        f"https://ipinfo.io/{indicator}/json",
        params={"token": token},
    )
    if not data or "_error" in data or "_http_status" in data:
        return {}

    return {
        "malicious": False,  # IPinfo is informational only
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "org": data.get("org"),
        "timezone": data.get("timezone"),
        "hostname": data.get("hostname"),
    }


# ── 4. URLScan.io ────────────────────────────────────────────

async def urlscan(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return {"_unavailable": "no URLSCAN_API_KEY"}

    data = await _safe_get_json(
        client,
        "https://urlscan.io/api/v1/search/",
        headers={"api-key": api_key},
        params={"q": f"domain:{indicator}", "size": 5},
    )
    if not data or "_error" in data or "_http_status" in data:
        return {}

    results = data.get("results", [])
    malicious = any(
        r.get("verdicts", {}).get("overall", {}).get("malicious", False)
        for r in results
    )
    return {
        "malicious": malicious,
        "scan_count": len(results),
        "latest_screenshot": results[0].get("screenshot") if results else None,
    }


# ── 5. Google Safe Browsing ──────────────────────────────────

async def google_safe_browsing(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return {"_unavailable": "no GOOGLE_SAFE_BROWSING_API_KEY"}

    payload = {
        "client": {"clientId": "pramaan", "clientVersion": "2.4.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{indicator}" if not indicator.startswith("http") else indicator}],
        },
    }

    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
        if r.status_code != 200:
            return {}
        data = r.json()
    except Exception:
        return {}

    matches = data.get("matches", [])
    return {
        "malicious": len(matches) > 0,
        "threat_types": [m.get("threatType") for m in matches],
        "platform_types": [m.get("platformType") for m in matches],
    }


# ── 6. ICANN RDAP (FREE) ─────────────────────────────────────

async def rdap(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    data = await _safe_get_json(client, f"https://rdap.org/domain/{indicator}")
    if not data or "_error" in data or "_http_status" in data:
        return {}

    # Find registration date
    registered = None
    for event in data.get("events", []):
        if event.get("eventAction") in ("registration", "registered"):
            registered = event.get("eventDate")
            break

    # Find registrar
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            break

    return {
        "malicious": False,  # informational
        "registered": registered,
        "registrar": registrar,
        "status": data.get("status", []),
    }


# ── 7. Authoritative DNS Resolver (FREE) ─────────────────────

async def dns_resolver(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    def _resolve():
        result = {"a_records": [], "mx_records": [], "ns_records": [], "txt_records": []}
        try:
            for rdata in dns.resolver.resolve(indicator, "A"):
                result["a_records"].append(str(rdata))
        except Exception:
            pass
        try:
            for rdata in dns.resolver.resolve(indicator, "MX"):
                result["mx_records"].append(str(rdata.exchange))
        except Exception:
            pass
        try:
            for rdata in dns.resolver.resolve(indicator, "NS"):
                result["ns_records"].append(str(rdata.target))
        except Exception:
            pass
        try:
            for rdata in dns.resolver.resolve(indicator, "TXT"):
                result["txt_records"].append(str(rdata)[:200])
        except Exception:
            pass
        return result

    # Run blocking DNS in a thread
    data = await asyncio.get_event_loop().run_in_executor(None, _resolve)

    # Simple heuristic: no records at all → suspicious
    total_records = sum(len(v) for v in data.values())
    data["malicious"] = total_records == 0
    return data


# ── 8. Shodan ────────────────────────────────────────────────

async def shodan(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"_unavailable": "no SHODAN_API_KEY"}
    if not _looks_like_ip(indicator):
        return {"_skipped": "only supports IPs"}

    data = await _safe_get_json(
        client,
        f"https://api.shodan.io/shodan/host/{indicator}",
        params={"key": api_key},
    )
    if not data or "_error" in data or "_http_status" in data:
        return {}

    return {
        "malicious": bool(data.get("tags") and any("malware" in t.lower() for t in data["tags"])),
        "ports": data.get("ports", []),
        "org": data.get("org"),
        "os": data.get("os"),
        "country": data.get("country_name"),
        "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
    }


# ── 9. Censys ────────────────────────────────────────────────

async def censys(indicator: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return {"_unavailable": "no CENSYS_API_ID/SECRET"}

    try:
        r = await client.get(
            f"https://search.censys.io/api/v2/hosts/{indicator}",
            auth=(api_id, api_secret),
            timeout=TIMEOUT_SECONDS,
        )
        if r.status_code != 200:
            return {}
        data = r.json()
    except Exception:
        return {}

    services = data.get("result", {}).get("services", [])
    return {
        "malicious": False,  # informational
        "service_count": len(services),
        "services": [
            {"port": s.get("port"), "service_name": s.get("service_name")}
            for s in services[:10]
        ],
        "country": data.get("result", {}).get("location", {}).get("country"),
    }


# ── Utilities ────────────────────────────────────────────────

def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    if ":" in value and len(value) > 4:
        return True
    return False


# ── Provider registry ────────────────────────────────────────

PROVIDERS = {
    "virustotal": virustotal,
    "abuseipdb": abuseipdb,
    "ipinfo": ipinfo,
    "urlscan": urlscan,
    "google_safe_browsing": google_safe_browsing,
    "rdap": rdap,
    "dns_resolver": dns_resolver,
    "shodan": shodan,
    "censys": censys,
}


def list_providers():
    return list(PROVIDERS.keys())
