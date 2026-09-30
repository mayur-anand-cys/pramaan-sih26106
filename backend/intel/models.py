"""
Data models for the PRAMAAN Threat Intel Aggregator.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ProviderStatus(str, Enum):
    """Status of a provider call result."""
    LIVE = "live"           # freshly fetched from the API
    CACHED = "cached"       # served from cache
    UNAVAILABLE = "unavailable"  # API failed, timed out, or not configured


class IndicatorType(str, Enum):
    """Type of IOC being enriched."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


@dataclass
class ProviderResult:
    """Result from a single threat intel provider."""
    provider: str
    status: ProviderStatus
    indicator: str
    indicator_type: IndicatorType
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["indicator_type"] = self.indicator_type.value
        return d


@dataclass
class AggregatedResult:
    """Aggregated enrichment result from all providers."""
    indicator: str
    indicator_type: IndicatorType
    providers: List[ProviderResult] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    threat_score: int = 0
    verdict: str = "unknown"  # clean / suspicious / malicious / unknown
    sources_live: int = 0
    sources_cached: int = 0
    sources_unavailable: int = 0
    total_duration_ms: int = 0

    def add_result(self, result: ProviderResult) -> None:
        self.providers.append(result)
        if result.status == ProviderStatus.LIVE:
            self.sources_live += 1
        elif result.status == ProviderStatus.CACHED:
            self.sources_cached += 1
        else:
            self.sources_unavailable += 1

    def finalize(self) -> None:
        """Compute verdict + threat_score + dedupe tags after all providers returned."""
        # Deduplicate tags using set
        self.tags = sorted(set(self.tags))

        # Threat score: LIVE/CACHED results with positive hits
        hits = sum(
            1 for p in self.providers
            if p.status in (ProviderStatus.LIVE, ProviderStatus.CACHED)
            and p.data.get("malicious", False)
        )

        if hits == 0:
            self.verdict = "clean"
            self.threat_score = 0
        elif hits <= 2:
            self.verdict = "suspicious"
            self.threat_score = min(60, 30 * hits)
        else:
            self.verdict = "malicious"
            self.threat_score = min(100, 30 * hits)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "verdict": self.verdict,
            "threat_score": self.threat_score,
            "tags": self.tags,
            "summary": {
                "live": self.sources_live,
                "cached": self.sources_cached,
                "unavailable": self.sources_unavailable,
                "total": len(self.providers),
            },
            "total_duration_ms": self.total_duration_ms,
            "providers": [p.to_dict() for p in self.providers],
        }


def detect_indicator_type(value: str) -> IndicatorType:
    """Auto-detect whether a string is an IP, domain, or URL."""
    v = value.strip().lower()

    # URL
    if v.startswith("http://") or v.startswith("https://"):
        return IndicatorType.URL

    # IPv4 (simple check)
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return IndicatorType.IP

    # IPv6 (has colons)
    if ":" in v and len(v) > 4:
        return IndicatorType.IP

    # Domain (has a dot, no spaces)
    if "." in v and " " not in v:
        return IndicatorType.DOMAIN

    return IndicatorType.DOMAIN  # fallback
