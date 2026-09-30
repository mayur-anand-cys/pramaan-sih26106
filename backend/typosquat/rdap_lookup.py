"""
RDAP-based domain age lookup for PRAMAAN.
Uses the free rdap.org bootstrap service (no API key required).
"""
import requests
from datetime import datetime, timezone
from typing import Optional, Dict
from functools import lru_cache

RDAP_BASE = "https://rdap.org/domain/"
TIMEOUT = 8
FRESH_DOMAIN_THRESHOLD_DAYS = 180


@lru_cache(maxsize=512)
def lookup_domain_age(domain: str) -> Optional[Dict]:
    """
    Look up registration date for a domain via RDAP.
    Returns dict with domain age info, or a dict with error set on failure.
    """
    try:
        resp = requests.get(f"{RDAP_BASE}{domain}", timeout=TIMEOUT)
        if resp.status_code != 200:
            return {
                "domain": domain,
                "registered": None,
                "age_days": None,
                "is_fresh": False,
                "registrar": None,
                "error": f"RDAP returned {resp.status_code}",
            }

        data = resp.json()

        registered = None
        for event in data.get("events", []):
            if event.get("eventAction") in ("registration", "registered"):
                registered = event.get("eventDate")
                break

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

        age_days = None
        is_fresh = False
        if registered:
            try:
                reg_dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - reg_dt).days
                is_fresh = age_days < FRESH_DOMAIN_THRESHOLD_DAYS
            except (ValueError, TypeError):
                pass

        return {
            "domain": domain,
            "registered": registered,
            "age_days": age_days,
            "is_fresh": is_fresh,
            "registrar": registrar,
            "error": None,
        }

    except requests.RequestException as e:
        return {
            "domain": domain,
            "registered": None,
            "age_days": None,
            "is_fresh": False,
            "registrar": None,
            "error": str(e),
        }


def is_domain_fresh(domain: str) -> bool:
    info = lookup_domain_age(domain)
    return bool(info and info.get("is_fresh"))


def clear_cache():
    lookup_domain_age.cache_clear()
