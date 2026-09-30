"""
Tests for the Threat Intel Aggregator (Issue #9).
Run: python tests/test_intel_aggregator.py
"""
import asyncio
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.intel.aggregator import enrich, get_cache_stats
from backend.intel.cache import reset_cache_for_tests
from backend.intel.models import (
    AggregatedResult,
    IndicatorType,
    ProviderResult,
    ProviderStatus,
    detect_indicator_type,
)
from backend.intel.providers import PROVIDERS, list_providers


def test_provider_count():
    names = list_providers()
    expected = {
        "virustotal", "abuseipdb", "ipinfo", "urlscan",
        "google_safe_browsing", "rdap", "dns_resolver",
        "shodan", "censys",
    }
    assert len(names) == 9, f"Expected 9 providers, got {len(names)}"
    assert set(names) == expected, f"Missing or extra: {set(names) ^ expected}"
    print(f"   [OK] 9 providers registered")


def test_indicator_type_detection():
    assert detect_indicator_type("8.8.8.8") == IndicatorType.IP
    assert detect_indicator_type("1.1.1.1") == IndicatorType.IP
    assert detect_indicator_type("google.com") == IndicatorType.DOMAIN
    assert detect_indicator_type("https://evil.com/x") == IndicatorType.URL
    print("   [OK] Indicator type detection works")


@pytest.mark.network
def test_enrichment_free_providers():
    async def run():
        return await enrich("example.com", providers=["rdap", "dns_resolver"])
    r = asyncio.run(run())
    d = r.to_dict()
    assert d["indicator"] == "example.com"
    assert d["indicator_type"] == "domain"
    assert len(d["providers"]) == 2
    assert d["summary"]["total"] == 2
    assert d["summary"]["live"] + d["summary"]["cached"] >= 1
    print(f"   [OK] Enriched example.com: verdict={d['verdict']} live={d['summary']['live']} cached={d['summary']['cached']}")


@pytest.mark.network
def test_cache_hit_rate_above_60():
    """3 passes on same indicators -> cache hit rate > 60%."""
    reset_cache_for_tests()

    async def run():
        indicators = ["wikipedia.org", "example.org", "iana.org"]
        for _ in range(3):
            for ind in indicators:
                await enrich(ind, providers=["rdap", "dns_resolver"])

    asyncio.run(run())

    stats = get_cache_stats()
    hit_rate = stats["hit_rate"]
    print(f"   [INFO] hits={stats['hits']} misses={stats['misses']} hit_rate={hit_rate:.0%}")
    assert hit_rate >= 0.60, f"Cache hit rate {hit_rate:.0%} < 60%"
    print(f"   [OK] Cache hit rate {hit_rate:.0%} >= 60%")


def test_graceful_degradation_no_keys():
    async def run():
        return await enrich("8.8.8.8", providers=[
            "virustotal", "abuseipdb", "ipinfo", "urlscan",
            "google_safe_browsing", "shodan", "censys",
        ])
    r = asyncio.run(run())
    d = r.to_dict()
    assert d["summary"]["total"] == 7
    print(f"   [OK] Graceful degradation: {d['summary']['unavailable']}/{d['summary']['total']} unavailable without keys")


@pytest.mark.network
def test_timeout_enforcement():
    from backend.intel import aggregator
    orig = aggregator.PROVIDERS["rdap"]

    async def slow_provider(indicator, client):
        await asyncio.sleep(10)
        return {"malicious": False}

    aggregator.PROVIDERS["rdap"] = slow_provider
    try:
        async def run():
            return await enrich("slow-test-domain.com", providers=["rdap"], use_cache=False)
        r = asyncio.run(run())
        d = r.to_dict()
        assert d["providers"][0]["status"] == "unavailable"
        assert "timeout" in d["providers"][0]["error"].lower()
        assert d["total_duration_ms"] < 6000, f"Took {d['total_duration_ms']}ms"
        print(f"   [OK] Timeout enforced: {d['total_duration_ms']}ms (limit 4s)")
    finally:
        aggregator.PROVIDERS["rdap"] = orig


def test_tag_deduplication():
    r = AggregatedResult(indicator="test.com", indicator_type=IndicatorType.DOMAIN)
    r.tags = ["malicious:vt", "malicious:vt", "fresh_domain", "malicious:vt"]
    r.finalize()
    assert len(r.tags) == len(set(r.tags))
    assert r.tags == sorted(set(r.tags))
    print(f"   [OK] Tags deduplicated: {r.tags}")


def test_verdict_computation():
    r = AggregatedResult(indicator="clean.com", indicator_type=IndicatorType.DOMAIN)
    r.finalize()
    assert r.verdict == "clean"
    assert r.threat_score == 0

    r = AggregatedResult(indicator="sus.com", indicator_type=IndicatorType.DOMAIN)
    r.add_result(ProviderResult(
        provider="virustotal", status=ProviderStatus.LIVE,
        indicator="sus.com", indicator_type=IndicatorType.DOMAIN,
        data={"malicious": True},
    ))
    r.finalize()
    assert r.verdict == "suspicious"
    assert 0 < r.threat_score <= 60

    r = AggregatedResult(indicator="bad.com", indicator_type=IndicatorType.DOMAIN)
    for p in ["virustotal", "abuseipdb", "google_safe_browsing"]:
        r.add_result(ProviderResult(
            provider=p, status=ProviderStatus.LIVE,
            indicator="bad.com", indicator_type=IndicatorType.DOMAIN,
            data={"malicious": True},
        ))
    r.finalize()
    assert r.verdict == "malicious"
    assert r.threat_score == 90
    print("   [OK] Verdict computation correct")


def main():
    print("\n[TEST] Threat Intel Aggregator (Issue #9)\n")
    tests = [
        ("9 providers registered", test_provider_count),
        ("Indicator type detection", test_indicator_type_detection),
        ("Enrichment (free providers)", test_enrichment_free_providers),
        ("Cache hit rate >= 60%", test_cache_hit_rate_above_60),
        ("Graceful degradation", test_graceful_degradation_no_keys),
        ("Timeout enforcement", test_timeout_enforcement),
        ("Tag deduplication", test_tag_deduplication),
        ("Verdict computation", test_verdict_computation),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        print(f"[RUN ] {name}")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERR ] {name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n[SUMMARY] {passed} passed, {failed} failed\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
