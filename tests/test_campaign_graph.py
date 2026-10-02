"""
Tests for campaign graph adapter + SOC graph panel (Issue #78).
Run: python tests/test_campaign_graph.py
"""
import sys
import networkx as nx
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import graph_engine


# ── Fixtures ────────────────────────────────────────────────

FAKE_CAMPAIGN = {
    "campaign_id": "CAMP-001",
    "nodes": [
        {"id": "CAMP-001", "type": "Campaign", "label": "CAMP-001"},
        {"id": "email-1", "type": "Email", "label": "Re: Wire transfer", "threat_score": 82},
        {"id": "email-2", "type": "Email", "label": "Fwd: Invoice", "threat_score": 71},
        {"id": "evil.ru", "type": "Domain", "label": "evil.ru"},
        {"id": "203.0.113.5", "type": "IP", "label": "203.0.113.5"},
    ],
    "edges": [
        {"source": "CAMP-001", "target": "email-1", "label": "PART_OF_CAMPAIGN"},
        {"source": "CAMP-001", "target": "email-2", "label": "PART_OF_CAMPAIGN"},
        {"source": "email-1", "target": "evil.ru", "label": "SENT_FROM_DOMAIN"},
        {"source": "email-1", "target": "203.0.113.5", "label": "SENT_FROM_IP"},
    ],
}


# ── Test 1: Adapter returns proper graph_data shape ────────

def test_adapter_shape():
    # Monkey-patch the queries module
    import backend.graph.queries as q
    orig = q.get_campaign_graph
    q.get_campaign_graph = lambda cid: FAKE_CAMPAIGN
    try:
        gd = graph_engine.build_campaign_graph("CAMP-001")
        assert gd["num_nodes"] == 5, gd["num_nodes"]
        assert gd["num_edges"] == 4, gd["num_edges"]
        assert isinstance(gd["graph"], nx.DiGraph)
        assert gd["campaign_id"] == "CAMP-001"
    finally:
        q.get_campaign_graph = orig
    print("   [OK] Adapter returns correct shape (5 nodes, 4 edges)")


# ── Test 2: Numeric shortcut → CAMP-NNN lookup ─────────────

def test_numeric_shortcut():
    import backend.graph.queries as q
    orig = q.get_campaign_graph
    calls = []

    def fake(cid):
        calls.append(cid)
        if cid == "CAMP-001":
            return FAKE_CAMPAIGN
        return {"campaign_id": cid, "nodes": [], "edges": []}

    q.get_campaign_graph = fake
    try:
        gd = graph_engine.build_campaign_graph("1")
        assert gd["num_nodes"] == 5, f"numeric fallback failed: {gd}"
        assert "CAMP-001" in calls, f"did not try padded id: {calls}"
    finally:
        q.get_campaign_graph = orig
    print("   [OK] Numeric '1' falls back to 'CAMP-001'")


# ── Test 3: Empty campaign → empty graph ───────────────────

def test_empty_campaign():
    import backend.graph.queries as q
    orig = q.get_campaign_graph
    q.get_campaign_graph = lambda cid: {"campaign_id": cid, "nodes": [], "edges": []}
    try:
        gd = graph_engine.build_campaign_graph("NOPE-999")
        assert gd["num_nodes"] == 0
        assert gd["num_edges"] == 0
        assert isinstance(gd["graph"], nx.DiGraph)
    finally:
        q.get_campaign_graph = orig
    print("   [OK] Empty campaign → 0-node graph")


# ── Test 4: generate_plotly_threat_graph works on adapter output ──

def test_plotly_renders():
    import backend.graph.queries as q
    orig = q.get_campaign_graph
    q.get_campaign_graph = lambda cid: FAKE_CAMPAIGN
    try:
        gd = graph_engine.build_campaign_graph("CAMP-001")
        fig = graph_engine.generate_plotly_threat_graph(gd)
        html = fig.to_html(include_plotlyjs=False, full_html=False)
        assert "plotly" in html.lower(), "no plotly markup"
        assert len(html) > 500, "suspiciously short html"
        assert "203.0.113.5" in html or "evil.ru" in html, "node labels missing"
    finally:
        q.get_campaign_graph = orig
    print(f"   [OK] Plotly renders HTML fragment ({len(html)} bytes)")


# ── Test 5: HTML fragment is self-contained (CDN plotly) ──

def test_html_fragment_shape():
    import backend.graph.queries as q
    orig = q.get_campaign_graph
    q.get_campaign_graph = lambda cid: FAKE_CAMPAIGN
    try:
        gd = graph_engine.build_campaign_graph("CAMP-001")
        fig = graph_engine.generate_plotly_threat_graph(gd)
        html = fig.to_html(include_plotlyjs="cdn", full_html=False)
        # Should NOT be a full document
        assert "<!DOCTYPE html>" not in html, "should be a fragment, not a full page"
        # Should reference plotly CDN
        assert "cdn.plot.ly" in html.lower() or "plotly" in html.lower()
    finally:
        q.get_campaign_graph = orig
    print("   [OK] HTML is a fragment, embeds plotly via CDN")


# ── Runner ─────────────────────────────────────────────────

def main():
    print("\n[TEST] Campaign Graph + SOC Panel (Issue #78)\n")
    tests = [
        ("Adapter returns proper graph_data shape", test_adapter_shape),
        ("Numeric '1' → 'CAMP-001' fallback", test_numeric_shortcut),
        ("Empty campaign → 0-node graph", test_empty_campaign),
        ("Plotly renders HTML", test_plotly_renders),
        ("HTML fragment shape (CDN, not full page)", test_html_fragment_shape),
    ]
    passed = failed = 0
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
