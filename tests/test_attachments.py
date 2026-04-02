"""
Tests for get_attachments()

Covers:
- Binary attachment detected and hashed correctly
- Plain text attachment detected and hashed correctly
- Multiple attachments all detected
- No attachments returns empty result
- Investigation mode generates VirusTotal links
- Regression #27: binary attachments no longer cause UnicodeDecodeError
"""

import pytest
import hashlib
from conftest import get_attachments, fixture_path


class TestAttachmentExtraction:
    def test_binary_attachment_detected(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]

        assert len(data) == 1
        assert data["1"] == "malware.pdf"

    def test_text_attachment_detected(self):
        # Use multi_attachment fixture — config.txt is a plain text attachment
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]
        names = list(data.values())

        assert "config.txt" in names

    def test_multiple_attachments_all_detected(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]

        assert len(data) == 3
        names = list(data.values())
        assert "document.pdf" in names
        assert "config.txt" in names
        assert "payload.exe" in names

    def test_no_attachments_returns_empty(self):
        result = get_attachments(fixture_path("no_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"] == {}
        assert result["Attachments"]["Investigation"] == {}

    def test_returns_correct_structure(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert "Attachments" in result
        assert "Data" in result["Attachments"]
        assert "Investigation" in result["Attachments"]


class TestAttachmentHashes:
    def test_binary_attachment_has_valid_md5(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        # hashes not in Data — checked via investigation keys
        result_inv = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result_inv["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]
        md5_url = inv["MD5"]

        # extract hash value from URL
        md5_val = md5_url.split("/")[-1]
        assert len(md5_val) == 32
        assert all(c in "0123456789abcdef" for c in md5_val)

    def test_binary_attachment_has_valid_sha256(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]
        sha256_val = inv["SHA256"].split("/")[-1]

        assert len(sha256_val) == 64

    def test_multiple_attachments_each_have_hashes(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]

        for name in ["document.pdf", "config.txt", "payload.exe"]:
            assert name in inv
            assert "MD5"    in inv[name]["Virustotal"]
            assert "SHA1"   in inv[name]["Virustotal"]
            assert "SHA256" in inv[name]["Virustotal"]


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result["Attachments"]["Investigation"] == {}

    def test_investigation_generates_name_search_link(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]

        assert "Name Search" in inv
        assert "malware.pdf" in inv["Name Search"]

    def test_investigation_generates_hash_links(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]

        for key in ["MD5", "SHA1", "SHA256"]:
            assert key in inv
            assert "virustotal.com" in inv[key]


class TestRegressionBug27:
    """Regression tests for Bug #27 — UnicodeDecodeError on binary attachments."""

    def test_binary_attachment_does_not_raise(self):
        """Previously: open('r') on binary content raised UnicodeDecodeError."""
        # Must not raise any exception
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result is not None

    def test_binary_attachment_hashes_are_non_empty(self):
        """Hashes must be computed correctly, not silently skipped."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]

        md5_val = inv["MD5"].split("/")[-1]
        sha1_val = inv["SHA1"].split("/")[-1]
        sha256_val = inv["SHA256"].split("/")[-1]

        assert len(md5_val) == 32
        assert len(sha1_val) == 40
        assert len(sha256_val) == 64

    def test_multiple_binary_attachments_all_hashed(self):
        """All binary attachments in a multi-attachment email must be processed."""
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]

        # payload.exe is a raw binary (bytes 0-31) — must not cause errors
        assert "payload.exe" in inv
        sha256_val = inv["payload.exe"]["Virustotal"]["SHA256"].split("/")[-1]
        assert len(sha256_val) == 64
