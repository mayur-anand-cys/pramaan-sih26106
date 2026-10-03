"""
Tests for backend/analytics/attack_map.py

Covers:
- Known category maps to the correct MITRE technique
- Unknown category falls back to the default mapping
- enrich_risk_factors adds attack_id and attack_name to each factor
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from backend.analytics.attack_map import (
    ATTACK_MAPPINGS,
    DEFAULT_MAPPING,
    map_to_attack,
    enrich_risk_factors,
)


class TestMapToAttack:
    """Tests for the map_to_attack() function."""

    def test_known_category_maps_correctly(self):
        """Authentication should map to T1556."""
        result = map_to_attack("Authentication")
        assert result["id"] == "T1556"
        assert result["name"] == "Modify Authentication Process"

    def test_typosquat_maps_correctly(self):
        """Typosquat should map to T1583.001."""
        result = map_to_attack("Typosquat")
        assert result["id"] == "T1583.001"
        assert "Domains" in result["name"]

    def test_unknown_category_returns_default(self):
        """Unknown category should fall back to the default (T1566)."""
        result = map_to_attack("SomeCategoryThatDoesNotExist")
        assert result == DEFAULT_MAPPING
        assert result["id"] == "T1566"

    def test_empty_string_returns_default(self):
        """Empty category should return the default."""
        result = map_to_attack("")
        assert result == DEFAULT_MAPPING


class TestEnrichRiskFactors:
    """Tests for the enrich_risk_factors() function."""

    def test_adds_attack_fields_to_each_factor(self):
        """Every factor should gain attack_id and attack_name."""
        factors = [
            {"category": "Authentication", "points": 20, "description": "SPF failed"},
            {"category": "Typosquat",      "points": 15, "description": "Lookalike domain"},
        ]
        enriched = enrich_risk_factors(factors)

        assert enriched[0]["attack_id"] == "T1556"
        assert enriched[0]["attack_name"] == "Modify Authentication Process"
        assert enriched[1]["attack_id"] == "T1583.001"
        assert enriched[1]["attack_name"] == "Acquire Infrastructure: Domains"

    def test_preserves_existing_fields(self):
        """Existing fields (points, description) should not be lost."""
        factors = [{"category": "ML Classifier", "points": 30, "description": "Model flagged"}]
        enrich_risk_factors(factors)

        assert factors[0]["points"] == 30
        assert factors[0]["description"] == "Model flagged"
        assert factors[0]["attack_id"] == "T1566"

    def test_unknown_category_uses_default(self):
        """Unknown categories should still get a default mapping applied."""
        factors = [{"category": "UnknownThing", "points": 5, "description": "???"}]
        enrich_risk_factors(factors)

        assert factors[0]["attack_id"] == DEFAULT_MAPPING["id"]
        assert factors[0]["attack_name"] == DEFAULT_MAPPING["name"]

    def test_empty_list_returns_empty(self):
        """Enriching an empty list should return an empty list."""
        assert enrich_risk_factors([]) == []

    def test_returns_same_list_reference(self):
        """The function should return the same list object (in-place mutation)."""
        factors = [{"category": "Authentication", "points": 10, "description": "x"}]
        result = enrich_risk_factors(factors)
        assert result is factors