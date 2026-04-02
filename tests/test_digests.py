"""
Tests for get_digests()

Covers:
- All 6 hashes computed (File MD5/SHA1/SHA256, Content MD5/SHA1/SHA256)
- Hash values are valid hex strings of correct length
- Investigation mode generates VirusTotal links for all hashes
- Investigation disabled returns empty investigation
- Same file produces same hashes (deterministic)
"""

import pytest
import hashlib
from conftest import get_digests, load_fixture, fixture_path


class TestDigestExtraction:
    def test_all_six_hashes_present(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)
        data = result["Digests"]["Data"]

        assert "File MD5"       in data
        assert "File SHA1"      in data
        assert "File SHA256"    in data
        assert "Content MD5"    in data
        assert "Content SHA1"   in data
        assert "Content SHA256" in data

    def test_md5_is_32_hex_chars(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File MD5"]) == 32
        assert len(data["Content MD5"]) == 32
        assert all(c in "0123456789abcdef" for c in data["File MD5"])

    def test_sha1_is_40_hex_chars(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File SHA1"]) == 40
        assert len(data["Content SHA1"]) == 40

    def test_sha256_is_64_hex_chars(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File SHA256"]) == 64
        assert len(data["Content SHA256"]) == 64

    def test_file_sha256_matches_direct_hash(self):
        """File hash must match independently computed hash of the file."""
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)

        with open(path, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()

        assert result["Digests"]["Data"]["File SHA256"] == expected

    def test_hashes_are_deterministic(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result1 = get_digests(mail_data, path, investigation=False)
        result2 = get_digests(mail_data, path, investigation=False)

        assert result1["Digests"]["Data"] == result2["Digests"]["Data"]

    def test_returns_correct_structure(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)

        assert "Digests" in result
        assert "Data" in result["Digests"]
        assert "Investigation" in result["Digests"]


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=False)
        assert result["Digests"]["Investigation"] == {}

    def test_investigation_generates_virustotal_links_for_all_hashes(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=True)
        inv = result["Digests"]["Investigation"]

        expected_keys = [
            "File MD5", "File SHA1", "File SHA256",
            "Content MD5", "Content SHA1", "Content SHA256"
        ]
        for key in expected_keys:
            assert key in inv
            assert "Virustotal" in inv[key]
            assert "virustotal.com" in inv[key]["Virustotal"]

    def test_investigation_links_contain_actual_hash_value(self):
        path = fixture_path("basic.eml")
        mail_data = load_fixture("basic.eml")
        result = get_digests(mail_data, path, investigation=True)

        file_md5 = result["Digests"]["Data"]["File MD5"]
        vt_link = result["Digests"]["Investigation"]["File MD5"]["Virustotal"]
        assert file_md5 in vt_link
