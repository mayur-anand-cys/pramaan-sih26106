"""
Tests for backend/typosquat/rdap_lookup.py

Covers:
- Successful RDAP lookup with valid registration data
- Domain freshness calculation
- HTTP error handling (non-200 status)
- Network failure handling
- Malformed date handling
- is_domain_fresh wrapper
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from backend.typosquat import rdap_lookup


class TestRdapLookup(unittest.TestCase):
    """Tests for the RDAP domain age lookup module."""

    def setUp(self):
        # Clear the lru_cache between tests so cached results don't leak
        rdap_lookup.clear_cache()

    # ------------------------------------------------------------------
    # Helper: build a fake requests.Response object
    # ------------------------------------------------------------------
    def _mock_response(self, status_code=200, json_data=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data or {}
        return resp

    # ------------------------------------------------------------------
    # Test 1: successful lookup of an old domain
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_successful_lookup_old_domain(self, mock_get):
        old_date = (
            datetime.now(timezone.utc) - timedelta(days=1000)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = self._mock_response(
            status_code=200,
            json_data={
                "events": [
                    {"eventAction": "registration", "eventDate": old_date}
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["version", {}, "text", "4.0"],
                             ["fn", {}, "text", "Example Registrar Inc."]]
                        ],
                    }
                ],
            },
        )

        result = rdap_lookup.lookup_domain_age("example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertIsNotNone(result["registered"])
        self.assertGreater(result["age_days"], 900)
        self.assertFalse(result["is_fresh"])
        self.assertEqual(result["registrar"], "Example Registrar Inc.")
        self.assertIsNone(result["error"])

    # ------------------------------------------------------------------
    # Test 2: fresh domain (under 180 days old)
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_fresh_domain_is_flagged(self, mock_get):
        fresh_date = (
            datetime.now(timezone.utc) - timedelta(days=30)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = self._mock_response(
            status_code=200,
            json_data={
                "events": [
                    {"eventAction": "registration", "eventDate": fresh_date}
                ],
                "entities": [],
            },
        )

        result = rdap_lookup.lookup_domain_age("brand-new-site.com")

        self.assertTrue(result["is_fresh"])
        self.assertLess(result["age_days"], rdap_lookup.FRESH_DOMAIN_THRESHOLD_DAYS)

    # ------------------------------------------------------------------
    # Test 3: HTTP non-200 response
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_http_error_status(self, mock_get):
        mock_get.return_value = self._mock_response(status_code=404, json_data={})

        result = rdap_lookup.lookup_domain_age("nonexistent-tld.xyz")

        self.assertEqual(result["domain"], "nonexistent-tld.xyz")
        self.assertIsNone(result["registered"])
        self.assertIsNone(result["age_days"])
        self.assertFalse(result["is_fresh"])
        self.assertIn("404", result["error"])

    # ------------------------------------------------------------------
    # Test 4: network exception
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_network_exception_is_caught(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("connection timed out")

        result = rdap_lookup.lookup_domain_age("unreachable.com")

        self.assertEqual(result["domain"], "unreachable.com")
        self.assertIsNone(result["registered"])
        self.assertFalse(result["is_fresh"])
        self.assertIsNotNone(result["error"])
        self.assertIn("timed out", result["error"])

    # ------------------------------------------------------------------
    # Test 5: malformed registration date
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_malformed_date_does_not_crash(self, mock_get):
        mock_get.return_value = self._mock_response(
            status_code=200,
            json_data={
                "events": [
                    {"eventAction": "registration", "eventDate": "not-a-date"}
                ],
                "entities": [],
            },
        )

        result = rdap_lookup.lookup_domain_age("baddate.com")

        # Should not raise. registered may be set, but age_days stays None.
        self.assertIsNone(result["age_days"])
        self.assertFalse(result["is_fresh"])
        self.assertIsNone(result["error"])

    # ------------------------------------------------------------------
    # Test 6: is_domain_fresh wrapper
    # ------------------------------------------------------------------
    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_is_domain_fresh_wrapper_true(self, mock_get):
        fresh_date = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = self._mock_response(
            status_code=200,
            json_data={
                "events": [
                    {"eventAction": "registration", "eventDate": fresh_date}
                ],
                "entities": [],
            },
        )

        self.assertTrue(rdap_lookup.is_domain_fresh("new-domain.com"))

    @patch("backend.typosquat.rdap_lookup.requests.get")
    def test_is_domain_fresh_wrapper_false(self, mock_get):
        old_date = (
            datetime.now(timezone.utc) - timedelta(days=2000)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = self._mock_response(
            status_code=200,
            json_data={
                "events": [
                    {"eventAction": "registration", "eventDate": old_date}
                ],
                "entities": [],
            },
        )

        self.assertFalse(rdap_lookup.is_domain_fresh("old-domain.com"))


if __name__ == "__main__":
    unittest.main()