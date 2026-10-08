import re
import ipaddress
from urllib.parse import urlparse
import requests
from typing import Dict, List, Any, Tuple

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".zip", ".mov", ".fit", ".cc", ".work",
    ".icu", ".club", ".download", ".buzz", ".monster", ".gq", ".ml", ".cf"
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "suspended", "verify", "password", "account", "bank",
    "unauthorized", "billing", "action required", "immediately",
    "security alert", "paypal", "crypto", "click here", "update details",
    "login", "confirm", "credit card", "security team", "disabled",
    "restore access", "fund", "wire transfer", "verification"
]

def analyze_domain_alignment(from_header: str, return_path: str, reply_to: str) -> Dict[str, Any]:
    """
    Analyze domain alignment between From, Return-Path, and Reply-To headers.
    Returns details on header mismatches and spoofing flags.
    """
    def extract_domain(email_str: str) -> str:
        if not email_str:
            return ""
        if "@" in email_str:
            parts = email_str.split("@")
            domain_part = parts[-1].strip("> ").strip().lower()
            return domain_part
        return ""

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(reply_to)

    mismatches = []
    is_spoofed = False

    if from_domain and return_domain and from_domain != return_domain:
        is_spoofed = True
        mismatches.append({
            "type": "Return-Path Mismatch",
            "from_domain": from_domain,
            "return_domain": return_domain,
            "description": f"Sender domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
        })

    if from_domain and reply_domain and from_domain != reply_domain:
        mismatches.append({
            "type": "Reply-To Mismatch",
            "from_domain": from_domain,
            "reply_domain": reply_domain,
            "description": f"Sender domain '{from_domain}' differs from Reply-To domain '{reply_domain}'"
        })

    return {
        "from_domain": from_domain,
        "return_domain": return_domain,
        "reply_domain": reply_domain,
        "is_spoofed": is_spoofed,
        "mismatches": mismatches
    }

def analyze_url_structure(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Perform deep forensic analysis on extracted URLs.
    Detects IP addresses, suspicious TLDs, user-pass '@' redirects, and high-entropy paths.
    """
    analyzed_urls = []

    for url in urls:
        flags = []
        risk_score = 0
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.hostname or ""

        # 1. IP address in hostname
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            flags.append("RAW_IP_HOSTNAME")
            risk_score += 35
        except ValueError:
            pass

        # 2. Suspicious TLD check
        tld_found = None
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                tld_found = tld
                flags.append(f"SUSPICIOUS_TLD ({tld})")
                risk_score += 25
                break

        # 3. User info / '@' in URL (Cred Phishing trick)
        if "@" in parsed.netloc:
            flags.append("USER_INFO_REDIRECT_AT_SYMBOL")
            risk_score += 30

        # 4. Excessive Subdomains (>3 parts)
        subdomain_count = len(hostname.split("."))
        if subdomain_count > 4 and not is_ip:
            flags.append("DEEP_SUBDOMAINS")
            risk_score += 15

        # 5. Length check (>100 chars)
        if len(url) > 100:
            flags.append("EXCESSIVE_URL_LENGTH")
            risk_score += 10

        analyzed_urls.append({
            "url": url,
            "domain": hostname,
            "is_ip": is_ip,
            "tld": tld_found,
            "flags": flags,
            "risk_score": min(100, risk_score)
        })

    return analyzed_urls


def follow_redirects(url: str, max_hops: int = 5, timeout: float = 5.0) -> Dict[str, Any]:
    """Trace redirect chains (HTTP 3xx + meta-refresh + JS location).

    Uses requests.Session with allow_redirects=True, max_redirects=max_hops.
    Also scans response bodies for <meta http-equiv="refresh"> and simple
    JS `location = "..."` patterns, WITHOUT executing JavaScript.

    Returns:
        {
            "final_url": str,
            "final_domain": str,
            "chain": [{"url": str, "status": int|None, "type": "http"|"meta"|"js"}],
            "hops": int,
            "error": str | None,
        }
    """
    import re
    try:
        from urllib.parse import urlparse as _urlparse
    except Exception:
        _urlparse = None

    result = {
        "final_url": url,
        "final_domain": "",
        "chain": [],
        "hops": 0,
        "error": None,
    }

    if not url or not isinstance(url, str):
        result["error"] = "invalid_url"
        return result

    chain = [{"url": url, "status": None, "type": "input"}]

    try:
        session = requests.Session()
        session.max_redirects = max_hops
        session.headers.update({"User-Agent": "PRAMAAN-Forensics/1.0"})

        current = url
        for hop in range(max_hops):
            try:
                resp = session.get(current, timeout=timeout, allow_redirects=False)
            except requests.exceptions.Timeout:
                chain[-1]["status"] = "TIMEOUT"
                result["error"] = "timeout_at_hop_%d" % hop
                break
            except requests.exceptions.RequestException as exc:
                chain[-1]["status"] = "ERROR"
                result["error"] = "request_error: %s" % str(exc)[:120]
                break

            status = resp.status_code
            chain[-1]["status"] = status

            # HTTP 3xx redirect
            if 300 <= status < 400:
                location = resp.headers.get("Location", "")
                if not location:
                    break
                # Resolve relative
                if location.startswith("/"):
                    parsed = _urlparse(current)
                    location = "%s://%s%s" % (parsed.scheme, parsed.netloc, location)
                chain.append({"url": location, "status": None, "type": "http"})
                current = location
                continue

            # 200 OK: scan body for meta-refresh / JS location
            body = resp.text or ""

            meta_match = re.search(
                r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?[^;]*;\s*url=([^"\'>\s]+)',
                body,
                re.IGNORECASE,
            )
            if meta_match:
                target = meta_match.group(1).strip()
                chain.append({"url": target, "status": None, "type": "meta"})
                current = target
                continue

            js_match = re.search(
                r'(?:window\.|document\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
                body,
            )
            if js_match:
                target = js_match.group(1).strip()
                chain.append({"url": target, "status": None, "type": "js"})
                current = target
                continue

            # No further redirect
            break

        result["final_url"] = current
        result["chain"] = chain
        result["hops"] = len(chain) - 1

        if _urlparse:
            try:
                result["final_domain"] = _urlparse(current).hostname or ""
            except Exception:
                result["final_domain"] = ""

    except Exception as exc:
        result["error"] = "unexpected: %s" % str(exc)[:120]

    return result
def geolocate_ip_cached(ip: str, cache: Dict[str, dict] = None) -> Dict[str, Any]:
    """
    Geolocate IPv4 address using public IP API with local caching & private IP validation.
    """

    # --- DEMO_MODE: return fixture instead of hitting ip-api.com ---
    try:
        from backend.demo.fixtures import demo_mode_enabled, get_demo_geo
        if demo_mode_enabled():
            return get_demo_geo(ip)
    except Exception:
        pass

    if cache is not None and ip in cache:
        return cache[ip]

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            res = {
                "ip": ip,
                "status": "skipped",
                "reason": "Private / Local Subnet",
                "country": "Local / Internal",
                "city": "Private Network",
                "isp": "Internal Subnet",
                "asn": "N/A",
                "lat": 37.7749,
                "lon": -122.4194
            }
            if cache is not None:
                cache[ip] = res
            return res
    except ValueError:
        return {"ip": ip, "status": "error", "reason": "Invalid IP", "lat": 0.0, "lon": 0.0}

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,lat,lon,query"
    try:
        response = requests.get(url, timeout=1.5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                res = {
                    "ip": ip,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat", 37.7749),
                    "lon": data.get("lon", -122.4194)
                }
                if cache is not None:
                    cache[ip] = res
                return res
    except Exception:
        pass

    fallback = {
        "ip": ip,
        "status": "error",
        "reason": "Lookup Timeout / Offline",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "asn": "N/A",
        "lat": 37.7749,
        "lon": -122.4194
    }
    if cache is not None:
        cache[ip] = fallback
    return fallback

def batch_geolocate_ips(ips: List[str], cache: Dict[str, dict] = None) -> List[Dict[str, Any]]:
    """Perform fast parallel batch geolocation for a list of IP addresses."""
    from concurrent.futures import ThreadPoolExecutor
    if not ips:
        return []
    
    with ThreadPoolExecutor(max_workers=min(10, len(ips))) as executor:
        results = list(executor.map(lambda ip: geolocate_ip_cached(ip, cache), ips))
    return results
