"""Tests for zero-knowledge forensic verification (ZKFV)."""
import zkfv


def test_same_file_produces_same_merkle_root():
    """Same bytes in = same Merkle root out."""
    sample = b"From: a@b.com\nSubject: Hello\n\nThis is the body."
    p1 = zkfv.generate_evidence_proof(sample)
    p2 = zkfv.generate_evidence_proof(sample)
    assert p1["merkle_root"] == p2["merkle_root"]
    assert p1["eml_sha256"] == p2["eml_sha256"]


def test_tampered_file_produces_different_merkle_root():
    """Different bytes in = different Merkle root out."""
    original = b"From: a@b.com\nSubject: Hello\n\nOriginal body."
    tampered = b"From: a@b.com\nSubject: Hello\n\nTAMPERED body."
    p_orig = zkfv.generate_evidence_proof(original)
    p_tamp = zkfv.generate_evidence_proof(tampered)
    assert p_orig["merkle_root"] != p_tamp["merkle_root"]


def test_tampered_file_fails_verification():
    """The critical security test: a tampered file MUST be rejected."""
    original = b"From: a@b.com\nSubject: Hello\n\nOriginal body."
    tampered = b"From: a@b.com\nSubject: Hello\n\nTAMPERED body."

    stored_proof = zkfv.generate_evidence_proof(original)
    is_valid, curr_root, expected_root = zkfv.verify_evidence_proof(tampered, stored_proof)

    assert is_valid is False, "SECURITY BUG: tampered file was accepted!"
    assert curr_root != expected_root


def test_untampered_file_passes_verification():
    """The positive case: a matching file MUST be accepted."""
    original = b"From: a@b.com\nSubject: Hello\n\nOriginal body."
    stored_proof = zkfv.generate_evidence_proof(original)
    is_valid, curr_root, expected_root = zkfv.verify_evidence_proof(original, stored_proof)
    assert is_valid is True
    assert curr_root == expected_root


def test_verification_does_not_crash_on_garbage_input():
    """Malformed input should return False, not raise an exception."""
    stored_proof = zkfv.generate_evidence_proof(b"real content")
    is_valid, curr_root, expected_root = zkfv.verify_evidence_proof(b"\x00\x01\x02 garbage", stored_proof)
    assert is_valid is False


def test_empty_input_does_not_crash():
    """Empty file should be handled gracefully."""
    stored_proof = zkfv.generate_evidence_proof(b"real content")
    is_valid, curr_root, expected_root = zkfv.verify_evidence_proof(b"", stored_proof)
    assert is_valid is False
