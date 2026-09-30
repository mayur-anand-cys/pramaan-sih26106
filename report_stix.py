# report_stix.py
"""STIX 2.1 export for forensic reports."""

import datetime

from stix2 import Bundle, Identity, Indicator, Malware, Relationship, File


def _defang(value):
    if not value:
        return value
    v = str(value)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    v = v.replace(".", "[.]")
    return v


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _classify_ioc(value):
    s = str(value).strip()
    if not s:
        return None
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ("ipv4", s)
    if s.startswith("http://") or s.startswith("https://"):
        return ("url", s)
    if "." in s and " " not in s and "/" not in s:
        return ("domain", s)
    return None


def generate_stix_bundle(
    sha256_hash,
    risk_score,
    risk_level,
    headers_dict,
    urls,
    ips,
    geo_data,
    risk_factors,
    ml_prob,
    merkle_root,
    filename="forensic_report.json",
    case_metadata=None,
    auth_results=None,
    relay_hops=None,
    xai_weights=None,
    contradictions=None,
    blockchain_tx="",
    etherscan_url="",
    custody_timeline=None,
    classification="",
):
    case_metadata = case_metadata or {}
    now = _now()

    identity = Identity(
        name="PRAMAAN Forensic Platform",
        identity_class="system",
        created=now,
        modified=now,
    )

    file_obj = File(
        name=case_metadata.get("Case ID", "unknown"),
        hashes={"SHA-256": sha256_hash},
    )

    objects = [identity, file_obj]

    if risk_score >= 35:
        malware = Malware(
            name=classification or "Suspicious Email Artifact",
            is_family=False,
            created=now,
            modified=now,
        )
        objects.append(malware)
        objects.append(Relationship(
            relationship_type="indicates",
            source_ref=file_obj.id,
            target_ref=malware.id,
            created=now,
            modified=now,
        ))

    seen = set()

    def _add_indicator(ioc_type, value):
        key = (ioc_type, value)
        if key in seen:
            return
        seen.add(key)

        if ioc_type == "ipv4":
            pattern = "[ipv4-addr:value = '" + value + "']"
            name = "Malicious IP: " + value
        elif ioc_type == "url":
            pattern = "[url:value = '" + value + "']"
            name = "Malicious URL: " + _defang(value)
        elif ioc_type == "domain":
            pattern = "[domain-name:value = '" + value + "']"
            name = "Malicious domain: " + value
        else:
            return

        try:
            ind = Indicator(
                name=name,
                pattern=pattern,
                pattern_type="stix",
                valid_from=now,
                created=now,
                modified=now,
                labels=["malicious-activity"],
                created_by_ref=identity.id,
            )
        except Exception:
            return

        objects.append(ind)
        objects.append(Relationship(
            relationship_type="indicates",
            source_ref=ind.id,
            target_ref=file_obj.id,
            created=now,
            modified=now,
        ))

    for u in urls or []:
        info = _classify_ioc(u)
        if info:
            _add_indicator(*info)

    for ip in ips or []:
        info = _classify_ioc(ip)
        if info:
            _add_indicator(*info)

    for g in geo_data or []:
        if g.get("status") == "success" and g.get("ip"):
            info = _classify_ioc(g["ip"])
            if info:
                _add_indicator(*info)

    bundle = Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(pretty=True)


def write_stix_report(path, **kwargs):
    doc = generate_stix_bundle(**kwargs)
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)