import unittest
from unittest.mock import patch, MagicMock

# Import the module under test
from backend.detection import auth_check

# The SPF function-level patch target: auth_check imports spf aliased as pyspf,
# so we patch via the module's reference to it.
SPF_PATCH = "backend.detection.auth_check.pyspf.check2"
DKIM_VERIFY_PATCH = "backend.detection.auth_check.dkim.verify"
DKIM_ARC_PATCH = "backend.detection.auth_check.dkim.arc_verify"
DNS_RESOLVE_PATCH = "backend.detection.auth_check.dns.resolver.resolve"


class TestAuthCheck(unittest.TestCase):
    def setUp(self):
        # Minimal well-formed email without any authentication headers
        self.base_email = (
            "From: Alice <alice@example.com>\r\n"
            "To: Bob <bob@recipient.com>\r\n"
            "Subject: Test\r\n"
            "\r\n"
            "Hello World\r\n"
        )

    # ------------------------------------------------------------------ SPF
    @patch(SPF_PATCH)
    def test_spf_header_and_dns_pass(self, mock_check2):
        """SPF on synthetic email with Received-SPF: pass -> header='pass'."""
        mock_check2.return_value = ("pass", "SPF pass explanation")
        raw = (
            "Received-SPF: pass (example.com: domain of sender@example.com"
            " designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;\r\n"
            "Return-Path: <sender@example.com>\r\n"
            + self.base_email
        )
        result = auth_check.check_spf(raw, source_ip="192.0.2.1")
        self.assertEqual(result["header_result"], "pass")
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["dns_result"], "pass")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["sender_ip"], "192.0.2.1")
        self.assertIn("SPF pass explanation", result["details"])

    @patch(SPF_PATCH)
    def test_spf_missing_header(self, mock_check2):
        """SPF on synthetic email with no SPF header -> header='none'."""
        mock_check2.return_value = ("none", "no SPF record")
        raw = "Return-Path: <sender@example.com>\r\n" + self.base_email
        result = auth_check.check_spf(raw, source_ip="192.0.2.1")
        self.assertEqual(result["header_result"], "none")
        # DNS call still ran (mocked), so dns_verified=True even for 'none'
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["dns_result"], "none")

    @patch(SPF_PATCH)
    def test_spf_no_source_ip_skips_dns(self, mock_check2):
        """SPF skips DNS check and returns dns_verified=False when source_ip is None."""
        raw = "Return-Path: <sender@example.com>\r\n" + self.base_email
        result = auth_check.check_spf(raw, source_ip=None)
        self.assertFalse(result["dns_verified"])
        self.assertEqual(result["dns_result"], "none")
        self.assertEqual(result["details"], "No source IP provided; SPF skipped")
        mock_check2.assert_not_called()

    @patch(SPF_PATCH)
    def test_spf_check2_unpack_three_tuple(self, mock_check2):
        """SPF correctly unpacks check2 results when 3 values are returned."""
        mock_check2.return_value = ("pass", 250, "sender IP matches SPF record")
        raw = "Return-Path: <sender@example.com>\r\n" + self.base_email
        result = auth_check.check_spf(raw, source_ip="192.0.2.1")
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["dns_result"], "pass")
        self.assertEqual(result["details"], "sender IP matches SPF record")

    # ------------------------------------------------------------------ DKIM
    @patch(DKIM_VERIFY_PATCH)
    def test_dkim_no_signature(self, mock_verify):
        """DKIM on email with no DKIM-Signature header -> domain='', no crash."""
        mock_verify.return_value = False
        raw = self.base_email  # no DKIM-Signature header
        result = auth_check.check_dkim(raw)
        self.assertEqual(result["header_result"], "none")
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["dns_result"], "fail")
        self.assertEqual(result["domain"], "")
        self.assertEqual(result["selector"], "")

    # ------------------------------------------------------------------ DMARC
    @patch(DNS_RESOLVE_PATCH)
    def test_dmarc_alignment_failure(self, mock_resolve):
        """DMARC with misaligned From/Return-Path -> alignment fails."""
        txt_record = MagicMock()
        txt_record.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@different.com"]
        mock_resolve.return_value = [txt_record]

        # From is 'different.com', SPF domain is 'example.com' -> no alignment
        spf_res = {"domain": "example.com", "dns_result": "pass"}
        dkim_res = {"domain": "example.org", "dns_result": "pass"}
        raw = (
            "From: Alice <alice@different.com>\r\n"
            "Return-Path: <sender@example.com>\r\n"
            + self.base_email
        )
        result = auth_check.check_dmarc(raw, spf_res, dkim_res)
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["policy"], "reject")
        self.assertFalse(result["spf_alignment"])
        self.assertFalse(result["dkim_alignment"])
        self.assertIn("DMARC policy reject", result["details"])

    @patch(DNS_RESOLVE_PATCH)
    def test_dmarc_multiple_txt_records_picks_dmarc1(self, mock_resolve):
        """DMARC lookup searches through multiple TXT records and picks the v=DMARC1 record."""
        spf_txt = MagicMock()
        spf_txt.strings = [b"v=spf1 include:_spf.google.com ~all"]
        dmarc_txt = MagicMock()
        dmarc_txt.strings = [b"v=DMARC1; p=quarantine; pct=100"]
        mock_resolve.return_value = [spf_txt, dmarc_txt]

        spf_res = {"domain": "example.com", "dns_result": "pass"}
        dkim_res = {"domain": "example.com", "dns_result": "pass"}
        raw = (
            "From: Alice <alice@example.com>\r\n"
            "Return-Path: <sender@example.com>\r\n"
            + self.base_email
        )
        result = auth_check.check_dmarc(raw, spf_res, dkim_res)
        self.assertTrue(result["dns_verified"])
        self.assertEqual(result["policy"], "quarantine")
        self.assertTrue(result["spf_alignment"])
        self.assertTrue(result["dkim_alignment"])

    @patch(DNS_RESOLVE_PATCH)
    def test_dmarc_no_dmarc_record_returns_none(self, mock_resolve):
        """DMARC lookup returns None when no record starts with v=DMARC1."""
        other_txt = MagicMock()
        other_txt.strings = [b"some random txt record"]
        mock_resolve.return_value = [other_txt]

        spf_res = {"domain": "example.com", "dns_result": "pass"}
        dkim_res = {"domain": "example.com", "dns_result": "pass"}
        raw = (
            "From: Alice <alice@example.com>\r\n"
            "Return-Path: <sender@example.com>\r\n"
            + self.base_email
        )
        result = auth_check.check_dmarc(raw, spf_res, dkim_res)
        self.assertFalse(result["dns_verified"])
        self.assertEqual(result["policy"], "none")
        self.assertEqual(result["details"], "DMARC record not found")

    # ------------------------------------------------------------------ ARC
    def test_check_arc_unsupported_when_missing_arc_verify(self):
        """check_arc returns unsupported fallback if dkim lacks arc_verify."""
        with patch.object(auth_check.dkim, "arc_verify", create=True):
            delattr(auth_check.dkim, "arc_verify")
            result = auth_check.check_arc(self.base_email)
            self.assertEqual(result["dns_result"], "unsupported")
            self.assertFalse(result["seal_verified"])
            self.assertEqual(
                result["details"], "ARC verification not supported by dkimpy version"
            )

    # ------------------------------------------------------------------ Trust score
    def test_compute_header_trust_score_max(self):
        """compute_header_trust_score returns 100 for all-pass input."""
        spf = {"dns_result": "pass"}
        dkim = {"dns_result": "pass"}
        dmarc = {
            "dns_result": "pass",
            "spf_alignment": True,
            "dkim_alignment": True,
            "policy": "reject",
        }
        arc = {"seal_verified": True}
        score = auth_check.compute_header_trust_score(spf, dkim, dmarc, arc)
        # 25(spf)+25(dkim)+20(dmarc)+5(spf_align)+5(dkim_align)+5(policy=reject)+15(arc) = 100
        self.assertEqual(score, 100)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_compute_header_trust_score_zero(self):
        """compute_header_trust_score returns 0 for all-fail input."""
        spf = {"dns_result": "fail"}
        dkim = {"dns_result": "fail"}
        dmarc = {
            "dns_result": "none",
            "spf_alignment": False,
            "dkim_alignment": False,
            "policy": "none",
        }
        arc = {"seal_verified": False}
        score = auth_check.compute_header_trust_score(spf, dkim, dmarc, arc)
        self.assertEqual(score, 0)

    # ------------------------------------------------------------------ Full workflow
    @patch(SPF_PATCH)
    @patch(DKIM_VERIFY_PATCH)
    @patch(DNS_RESOLVE_PATCH)
    @patch(DKIM_ARC_PATCH)
    def test_verify_email_auth_full_workflow(
        self, mock_arc, mock_resolve, mock_verify, mock_check2
    ):
        """verify_email_auth returns the full dict shape with expected values."""
        mock_check2.return_value = ("pass", "spf ok")
        mock_verify.return_value = True
        txt_record = MagicMock()
        txt_record.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        mock_resolve.return_value = [txt_record]
        mock_arc.return_value = True

        raw = (
            "Received-SPF: pass (example.com: domain of sender@example.com"
            " designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;\r\n"
            "Authentication-Results: example.com;"
            " dkim=pass header.i=@example.com;"
            " spf=pass smtp.mailfrom=example.com;"
            " dmarc=pass; arc=pass\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s2021; bh=...; b=...\r\n"
            "From: Alice <alice@example.com>\r\n"
            "Return-Path: <sender@example.com>\r\n"
            "To: Bob <bob@recipient.com>\r\n"
            "Subject: Test\r\n"
            "\r\n"
            "Hello World\r\n"
        )
        result = auth_check.verify_email_auth(raw, source_ip="192.0.2.1")

        # Top-level keys all present
        for key in ("spf", "dkim", "dmarc", "arc", "header_trust_score"):
            self.assertIn(key, result)

        # Individual results
        self.assertEqual(result["spf"]["dns_result"], "pass")
        self.assertEqual(result["dkim"]["dns_result"], "pass")
        self.assertEqual(result["dmarc"]["policy"], "reject")
        self.assertTrue(result["arc"]["seal_verified"])

        # Score in valid range; with SPF+DKIM pass and DMARC(reject)+ARC = 100
        self.assertEqual(result["header_trust_score"], 100)

    # ------------------------------------------------------------------ Malformed email
    @patch(SPF_PATCH)
    @patch(DKIM_VERIFY_PATCH)
    def test_malformed_email_graceful(self, mock_verify, mock_check2):
        """Malformed email does not raise; returns safe default dicts."""
        mock_check2.side_effect = Exception("DNS error")
        mock_verify.side_effect = Exception("DKIM error")
        raw = "THIS IS NOT A VALID EMAIL"
        # Must not raise
        result = auth_check.verify_email_auth(raw)

        self.assertIsInstance(result, dict)
        for key in ("spf", "dkim", "dmarc", "arc"):
            self.assertIn(key, result)

        self.assertFalse(result["spf"]["dns_verified"])
        self.assertFalse(result["dkim"]["dns_verified"])
        self.assertFalse(result["arc"]["seal_verified"])


if __name__ == "__main__":
    unittest.main()
