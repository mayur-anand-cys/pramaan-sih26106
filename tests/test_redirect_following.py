"""
Tests for URL redirect chain tracing.
Run: python -m pytest tests/test_redirect_following.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import requests_mock

from threat_intel import follow_redirects


def test_three_hop_chain():
    with requests_mock.Mocker() as m:
        m.get("http://a.example/", status_code=302, headers={"Location": "http://b.example/"})
        m.get("http://b.example/", status_code=302, headers={"Location": "http://c.example/"})
        m.get("http://c.example/", status_code=200, text="<html>final</html>")

        r = follow_redirects("http://a.example/")
        assert r["error"] is None
        assert r["final_url"] == "http://c.example/"
        assert r["final_domain"] == "c.example"
        assert r["hops"] == 2
        assert len(r["chain"]) == 3
        assert r["chain"][0]["url"] == "http://a.example/"
        assert r["chain"][-1]["url"] == "http://c.example/"
        print("   [OK] 3-hop chain -> " + r["final_url"])


def test_max_hops_cap():
    with requests_mock.Mocker() as m:
        for i in range(1, 10):
            m.get("http://h%d.example/" % i, status_code=302,
                  headers={"Location": "http://h%d.example/" % (i + 1)})

        r = follow_redirects("http://h1.example/", max_hops=5)
        assert r["hops"] <= 5
        print("   [OK] max hops capped at " + str(r["hops"]))


def test_meta_refresh_detection():
    with requests_mock.Mocker() as m:
        m.get("http://meta.example/", status_code=200,
              text='<meta http-equiv="refresh" content="0; url=http://evil.example/">')
        m.get("http://evil.example/", status_code=200, text="final")

        r = follow_redirects("http://meta.example/")
        types = [h["type"] for h in r["chain"]]
        assert "meta" in types
        assert r["final_url"] == "http://evil.example/"
        print("   [OK] meta-refresh detected -> " + r["final_url"])


def test_js_location_detection():
    with requests_mock.Mocker() as m:
        m.get("http://js.example/", status_code=200,
              text='<script>window.location = "http://evil.example/payload";</script>')
        m.get("http://evil.example/payload", status_code=200, text="final")

        r = follow_redirects("http://js.example/")
        types = [h["type"] for h in r["chain"]]
        assert "js" in types
        assert "evil.example" in r["final_url"]
        print("   [OK] JS redirect detected -> " + r["final_url"])


def test_timeout_handling():
    import requests
    with requests_mock.Mocker() as m:
        m.get("http://slow.example/", exc=requests.exceptions.Timeout)

        r = follow_redirects("http://slow.example/", timeout=0.1)
        assert r["error"] is not None
        assert "timeout" in r["error"].lower()
        print("   [OK] timeout handled -> " + r["error"])


def test_invalid_url():
    r = follow_redirects("")
    assert r["error"] == "invalid_url"
    print("   [OK] invalid URL short-circuits")