"""
Tests for duplicate attachment detection (Enhancement #51)

Covers:
- Duplicate Warning key present when duplicates exist
- Duplicate Warning key absent when no duplicates
- Duplicate Warning key absent when investigation=False
- Duplicate Warning maps SHA256 to list of filenames
- List contains all filenames sharing the hash
- Unique attachment not included in Duplicate Warning
- SHA256 key in Duplicate Warning is a valid 64-char hex string
- Two identical attachments produce one SHA256 entry with two filenames
- Regular investigation entries still present alongside Duplicate Warning
- Regression #51: duplicate attachments previously silently undetected
"""

import pytest
import hashlib
from conftest import get_attachments, fixture_path


class TestDuplicateDetection:
    def test_duplicate_warning_present_when_duplicates_exist(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        assert "Duplicate Warning" in result["Attachments"]["Investigation"]

    def test_duplicate_warning_absent_when_no_duplicates(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        assert "Duplicate Warning" not in result["Attachments"]["Investigation"]

    def test_duplicate_warning_absent_when_investigation_false(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=False)
        assert "Duplicate Warning" not in result["Attachments"]["Investigation"]

    def test_duplicate_warning_maps_sha256_to_filenames(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        assert isinstance(warning, dict)
        # Each key is a SHA256, each value is a list
        for sha, names in warning.items():
            assert isinstance(sha, str)
            assert isinstance(names, list)

    def test_duplicate_warning_sha256_is_64_hex_chars(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        for sha in warning.keys():
            assert len(sha) == 64
            assert all(c in "0123456789abcdef" for c in sha)

    def test_duplicate_warning_contains_both_duplicate_filenames(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        all_names = [name for names in warning.values() for name in names]
        assert "invoice.pdf" in all_names
        assert "receipt.pdf" in all_names

    def test_unique_attachment_not_in_duplicate_warning(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        all_names = [name for names in warning.values() for name in names]
        assert "readme.txt" not in all_names

    def test_two_duplicates_produce_one_sha256_entry(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        assert len(warning) == 1

    def test_duplicate_sha256_entry_has_two_filenames(self):
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        sha, names = next(iter(warning.items()))
        assert len(names) == 2

    def test_duplicate_sha256_matches_actual_content_hash(self):
        """SHA256 key in Duplicate Warning must match the real hash of the duplicate content."""
        import email as email_mod
        import email.policy
        path = fixture_path("duplicate_attachments.eml")
        with open(path, "rb") as f:
            msg = email_mod.message_from_binary_file(f, policy=email_mod.policy.default)
        payloads = {}
        for part in msg.iter_attachments():
            fname = part.get_filename()
            payload = part.get_payload(decode=True)
            if payload is not None and fname in ("invoice.pdf", "receipt.pdf"):
                payloads[fname] = payload

        expected_sha = hashlib.sha256(payloads["invoice.pdf"]).hexdigest()
        assert payloads["invoice.pdf"] == payloads["receipt.pdf"]

        result = get_attachments(path, investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        assert expected_sha in warning

    def test_regular_investigation_entries_still_present(self):
        """VT links for individual attachments must still appear alongside Duplicate Warning."""
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]
        assert "invoice.pdf" in inv
        assert "receipt.pdf" in inv
        assert "readme.txt" in inv

    def test_no_attachments_no_duplicate_warning(self):
        result = get_attachments(fixture_path("no_attachment.eml"), investigation=True)
        assert "Duplicate Warning" not in result["Attachments"]["Investigation"]

    def test_single_attachment_no_duplicate_warning(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        assert "Duplicate Warning" not in result["Attachments"]["Investigation"]


class TestRegressionEnhancement51:
    """Regression tests for Enhancement #51 — duplicate attachments silently undetected."""

    def test_duplicate_content_detected_across_different_filenames(self):
        """invoice.pdf and receipt.pdf have identical content — must be flagged."""
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=True)
        warning = result["Attachments"]["Investigation"]["Duplicate Warning"]
        all_names = [name for names in warning.values() for name in names]
        assert "invoice.pdf" in all_names
        assert "receipt.pdf" in all_names

    def test_duplicate_warning_only_when_investigation_requested(self):
        """Duplicate Warning must not appear in Data section or without investigation flag."""
        result = get_attachments(fixture_path("duplicate_attachments.eml"), investigation=False)
        assert "Duplicate Warning" not in result["Attachments"]["Data"]
        assert "Duplicate Warning" not in result["Attachments"]["Investigation"]
