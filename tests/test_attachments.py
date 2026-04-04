"""
Tests for get_attachments()

Covers:
- Binary attachment detected and hashed correctly
- Plain text attachment detected and hashed correctly
- Image attachment (image/png MIME type) detected and hashed
- Multiple attachments all detected with sequential indexing
- No attachments returns empty result
- Attachments indexed from "1", sequential integers
- Attachment count matches data length
- Hash values are valid hex strings (MD5=32, SHA1=40, SHA256=64)
- MD5/SHA1/SHA256 each match independently computed value
- Hash is deterministic across calls
- Different attachments produce different hashes
- Investigation mode: VirusTotal links (name + all 3 hashes)
- Investigation mode: exact VT URL format
- Investigation count matches data count
- Regression #27: binary attachments no longer cause UnicodeDecodeError
"""

import pytest
import hashlib
import email
import email.policy
from pathlib import Path
from conftest import get_attachments, fixture_path, FIXTURES_DIR


def get_raw_payload(eml_filename: str, attachment_filename: str) -> bytes:
    """Helper: extract raw decoded payload bytes from a fixture for direct hash comparison."""
    path = FIXTURES_DIR / eml_filename
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    for part in msg.iter_attachments():
        if part.get_filename() == attachment_filename:
            return part.get_payload(decode=True)
    raise ValueError(f"Attachment '{attachment_filename}' not found in {eml_filename}")


class TestAttachmentExtraction:
    def test_binary_attachment_detected(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]

        assert len(data) == 1
        assert data["1"] == "malware.pdf"

    def test_text_attachment_detected(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        names = list(result["Attachments"]["Data"].values())
        assert "config.txt" in names

    def test_multiple_attachments_all_detected(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]

        assert len(data) == 3
        names = list(data.values())
        assert "document.pdf" in names
        assert "config.txt"   in names
        assert "payload.exe"  in names

    def test_image_attachment_detected(self):
        """image/png MIME type must be detected like any other attachment."""
        result = get_attachments(fixture_path("image_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]

        assert len(data) == 1
        assert data["1"] == "logo.png"

    def test_no_attachments_returns_empty(self):
        result = get_attachments(fixture_path("no_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"] == {}
        assert result["Attachments"]["Investigation"] == {}

    def test_attachments_indexed_from_one(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        keys = list(result["Attachments"]["Data"].keys())
        assert keys[0] == "1"

    def test_attachment_count_matches_data_length(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        assert len(result["Attachments"]["Data"]) == 3

    def test_multiple_attachments_sequential_indexing(self):
        """Keys for 3 attachments must be '1', '2', '3' in order."""
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        keys = list(result["Attachments"]["Data"].keys())
        assert keys == ["1", "2", "3"]

    def test_returns_correct_structure(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert "Attachments" in result
        assert "Data"        in result["Attachments"]
        assert "Investigation" in result["Attachments"]


class TestAttachmentHashes:
    def test_binary_attachment_md5_is_32_hex_chars(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        md5_val = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["MD5"].split("/")[-1]
        assert len(md5_val) == 32
        assert all(c in "0123456789abcdef" for c in md5_val)

    def test_binary_attachment_sha1_is_40_hex_chars(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        sha1_val = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["SHA1"].split("/")[-1]
        assert len(sha1_val) == 40

    def test_binary_attachment_sha256_is_64_hex_chars(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        sha256_val = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["SHA256"].split("/")[-1]
        assert len(sha256_val) == 64

    def test_attachment_sha256_matches_direct_computation(self):
        """Hash in output must match hashlib computed directly from the raw payload."""
        payload = get_raw_payload("binary_attachment.eml", "malware.pdf")
        expected_sha256 = hashlib.sha256(payload).hexdigest()

        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        actual_sha256 = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["SHA256"].split("/")[-1]

        assert actual_sha256 == expected_sha256

    def test_attachment_md5_matches_direct_computation(self):
        payload = get_raw_payload("binary_attachment.eml", "malware.pdf")
        expected_md5 = hashlib.md5(payload).hexdigest()

        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        actual_md5 = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["MD5"].split("/")[-1]

        assert actual_md5 == expected_md5

    def test_attachment_sha1_matches_direct_computation(self):
        payload = get_raw_payload("binary_attachment.eml", "malware.pdf")
        expected_sha1 = hashlib.sha1(payload).hexdigest()

        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        actual_sha1 = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["SHA1"].split("/")[-1]

        assert actual_sha1 == expected_sha1

    def test_image_attachment_sha256_matches_direct_computation(self):
        payload = get_raw_payload("image_attachment.eml", "logo.png")
        expected = hashlib.sha256(payload).hexdigest()

        result = get_attachments(fixture_path("image_attachment.eml"), investigation=True)
        actual = result["Attachments"]["Investigation"]["logo.png"]["Virustotal"]["SHA256"].split("/")[-1]

        assert actual == expected

    def test_attachment_hashes_are_deterministic(self):
        result1 = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        result2 = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)

        inv1 = result1["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]
        inv2 = result2["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]

        assert inv1["MD5"]    == inv2["MD5"]
        assert inv1["SHA1"]   == inv2["SHA1"]
        assert inv1["SHA256"] == inv2["SHA256"]

    def test_multiple_attachments_each_have_all_three_hashes(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]

        for name in ["document.pdf", "config.txt", "payload.exe"]:
            vt = inv[name]["Virustotal"]
            assert "MD5"    in vt
            assert "SHA1"   in vt
            assert "SHA256" in vt

    def test_different_attachments_produce_different_hashes(self):
        """Two attachments with different content must have different SHA256 values."""
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]

        sha256_pdf = inv["document.pdf"]["Virustotal"]["SHA256"].split("/")[-1]
        sha256_txt = inv["config.txt"]["Virustotal"]["SHA256"].split("/")[-1]
        sha256_exe = inv["payload.exe"]["Virustotal"]["SHA256"].split("/")[-1]

        assert sha256_pdf != sha256_txt
        assert sha256_pdf != sha256_exe
        assert sha256_txt != sha256_exe


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result["Attachments"]["Investigation"] == {}

    def test_virustotal_hash_url_exact_format(self):
        """VT URL must be virustotal.com/gui/search/{hash}."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        sha256_url = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["SHA256"]
        sha256_val = sha256_url.split("/")[-1]

        assert sha256_url == f"https://www.virustotal.com/gui/search/{sha256_val}"

    def test_virustotal_name_search_url_exact_format(self):
        """VT Name Search URL must be virustotal.com/gui/search/{filename}."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        name_url = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]["Name Search"]

        assert name_url == "https://www.virustotal.com/gui/search/malware.pdf"

    def test_image_attachment_investigation_links(self):
        """Image attachments must produce the same investigation structure as binary."""
        result = get_attachments(fixture_path("image_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["logo.png"]["Virustotal"]

        assert "Name Search" in inv
        assert "MD5"    in inv
        assert "SHA1"   in inv
        assert "SHA256" in inv
        assert "logo.png" in inv["Name Search"]

    def test_investigation_generates_name_search_link(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]
        assert "Name Search" in inv
        assert "malware.pdf" in inv["Name Search"]

    def test_investigation_generates_all_hash_links(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]
        for key in ["MD5", "SHA1", "SHA256"]:
            assert key in inv
            assert "virustotal.com" in inv[key]

    def test_investigation_count_matches_data_count(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        assert len(result["Attachments"]["Data"]) == len(result["Attachments"]["Investigation"])

    def test_no_attachments_investigation_is_empty(self):
        result = get_attachments(fixture_path("no_attachment.eml"), investigation=True)
        assert result["Attachments"]["Investigation"] == {}


class TestRegressionBug27:
    """Regression tests for Bug #27 — UnicodeDecodeError on binary attachments."""

    def test_binary_attachment_does_not_raise(self):
        """Previously: open('r') on binary content raised UnicodeDecodeError."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result is not None

    def test_binary_attachment_hashes_are_non_empty(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]["malware.pdf"]["Virustotal"]

        assert len(inv["MD5"].split("/")[-1])    == 32
        assert len(inv["SHA1"].split("/")[-1])   == 40
        assert len(inv["SHA256"].split("/")[-1]) == 64

    def test_multiple_binary_attachments_all_hashed(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=True)
        inv = result["Attachments"]["Investigation"]

        assert "payload.exe" in inv
        assert len(inv["payload.exe"]["Virustotal"]["SHA256"].split("/")[-1]) == 64
