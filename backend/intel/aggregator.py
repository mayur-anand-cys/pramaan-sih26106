"""
Threat Intel Aggregator for PRAMAAN.

Runs all 9 providers in parallel with a 4-second timeout, caches results
for 30 days, and gracefully degrades when any API fails.
"""
import asyncio
import time
from typing import Any, Dict, List, Optional

import httpx

from .cache import get_cache
from .models import (
    AggregatedResult,
    IndicatorType,
    ProviderResult,
    ProviderStatus,
    detect_indicator_type,
)
from .providers import PROVIDERS, TIMEOUT_SECONDS


# ── Single provider execution with cache + timeout ───────────

async def _run_provider(
    name: str,
    func,
    indicator: str,
    indicator_type: IndicatorType,
    client: httpx.AsyncClient,
    use_cache: bool = True,
) -> ProviderResult:
    """Run one provider with cache check, timeout, and graceful error handling."""
    cache = get_cache()
    start = time.perf_counter()

    # 1. Try cache first
    if use_cache:
        cached = cache.get(indicator, name)
        if cached is not None:
            duration = int((time.perf_counter() - start) * 1000)
            return ProviderResult(
                provider=name,
                status=ProviderStatus.CACHED,
                indicator=indicator,
                indicator_type=indicator_type,
                data=cached,
                duration_ms=duration,
            )

    # 2. Call provider with hard timeout
    try:
        data = await asyncio.wait_for(
            func(indicator, client),
            timeout=TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        duration = int((time.perf_counter() - start) * 1000)
        return ProviderResult(
            provider=name,
            status=ProviderStatus.UNAVAILABLE,
            indicator=indicator,
            indicator_type=indicator_type,
            error=f"timeout after {TIMEOUT_SECONDS}s",
            duration_ms=duration,
        )
    except Exception as e:
        duration = int((time.perf_counter() - start) * 1000)
        return ProviderResult(
            provider=name,
            status=ProviderStatus.UNAVAILABLE,
            indicator=indicator,
            indicator_type=indicator_type,
            error=f"{type(e).__name__}: {e}",
            duration_ms=duration,
        )

    # 3. Handle "unavailable" markers returned by providers
    if not data:
        duration = int((time.perf_counter() - start) * 1000)
        return ProviderResult(
            provider=name,
            status=ProviderStatus.UNAVAILABLE,
            indicator=indicator,
            indicator_type=indicator_type,
            error="empty response",
            duration_ms=duration,
        )

    if "_unavailable" in data or "_skipped" in data:
        reason = data.get("_unavailable") or data.get("_skipped")
        duration = int((time.perf_counter() - start) * 1000)
        return ProviderResult(
            provider=name,
            status=ProviderStatus.UNAVAILABLE,
            indicator=indicator,
            indicator_type=indicator_type,
            error=reason,
            duration_ms=duration,
        )

    # 4. Cache successful result
    if use_cache:
        # Only cache if we got meaningful data (no _error)
        if "_error" not in data:
            cache.set(indicator, name, data)

    duration = int((time.perf_counter() - start) * 1000)
    return ProviderResult(
        provider=name,
        status=ProviderStatus.LIVE,
        indicator=indicator,
        indicator_type=indicator_type,
        data=data,
        duration_ms=duration,
    )


# ── Main public function ─────────────────────────────────────

async def enrich(
    indicator: str,
    indicator_type: Optional[IndicatorType] = None,
    use_cache: bool = True,
    providers: Optional[List[str]] = None,
) -> AggregatedResult:
    """
    Enrich an indicator by querying all 9 providers in parallel.

    Args:
        indicator: IP, domain, or URL
        indicator_type: auto-detected if None
        use_cache: whether to consult/populate cache
        providers: optional subset of provider names

    Returns:
        AggregatedResult
    """
    indicator = indicator.strip().lower()
    if indicator_type is None:
        indicator_type = detect_indicator_type(indicator)

    selected = providers if providers else list(PROVIDERS.keys())
    # Validate
    selected = [p for p in selected if p in PROVIDERS]

    start = time.perf_counter()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [
            _run_provider(
                name,
                PROVIDERS[name],
                indicator,
                indicator_type,
                client,
                use_cache=use_cache,
            )
            for name in selected
        ]
        results: List[ProviderResult] = await asyncio.gather(*tasks)

    # Aggregate
    agg = AggregatedResult(indicator=indicator, indicator_type=indicator_type)

    for r in results:
        agg.add_result(r)

        # Collect tags from successful results
        if r.status in (ProviderStatus.LIVE, ProviderStatus.CACHED):
            _extract_tags(r, agg.tags)

    agg.total_duration_ms = int((time.perf_counter() - start) * 1000)
    agg.finalize()
    return agg


def _extract_tags(result: ProviderResult, tags: List[str]) -> None:
    """Extract threat tags from a provider's data."""
    d = result.data
    if not d:
        return

    if d.get("malicious"):
        tags.append(f"malicious:{result.provider}")

    # Threat types (Safe Browsing)
    for t in d.get("threat_types", []) or []:
        if t:
            tags.append(str(t).lower())

    # Abuse score bands
    score = d.get("abuse_score")
    if isinstance(score, int):
        if score >= 75:
            tags.append("high_abuse")
        elif score >= 25:
            tags.append("moderate_abuse")

    # Shodan vulns
    if d.get("vulns"):
        tags.append("has_vulnerabilities")

    # DNS heuristic
    if result.provider == "dns_resolver" and d.get("malicious"):
        tags.append("no_dns_records")

    # Very fresh domain (RDAP)
    if result.provider == "rdap" and d.get("registered"):
        try:
            from datetime import datetime, timezone
            reg = datetime.fromisoformat(str(d["registered"]).replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - reg).days
            if age_days < 180:
                tags.append("fresh_domain")
        except Exception:
            pass


# ── Sync wrapper for FastAPI convenience ─────────────────────

def enrich_sync(indicator: str, **kwargs) -> Dict[str, Any]:
    """Blocking wrapper. Use in sync endpoints."""
    result = asyncio.run(enrich(indicator, **kwargs))
    return result.to_dict()


def get_cache_stats() -> Dict[str, Any]:
    return get_cache().get_stats()


__all__ = ["enrich", "enrich_sync", "get_cache_stats"]
