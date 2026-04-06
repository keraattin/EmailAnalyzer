"""
Tests for get_digests()

Covers:
- All 6 hashes computed (File MD5/SHA1/SHA256, Content MD5/SHA1/SHA256)
- Hash values are valid lowercase hex strings of correct length
- File MD5/SHA1/SHA256 each match independently computed hash
- Content MD5/SHA1/SHA256 each match independently computed hash
- File hash and content hash are independent code paths
- Two different files produce different hashes
- Hashes verified on multiple fixture files (not just basic.eml)
- Investigation mode generates VirusTotal links for all hashes
- Investigation links contain the actual hash value
- Investigation disabled returns empty investigation
- Same file produces same hashes (deterministic)
- Regression #31: file read once as binary, no double-open inconsistency
"""

import pytest
import hashlib
from conftest import get_digests, load_fixture, load_fixture_bytes, fixture_path


class TestDigestExtraction:
    def test_all_six_hashes_present(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        assert "File MD5"       in data
        assert "File SHA1"      in data
        assert "File SHA256"    in data
        assert "Content MD5"    in data
        assert "Content SHA1"   in data
        assert "Content SHA256" in data

    def test_md5_is_32_hex_chars(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File MD5"]) == 32
        assert len(data["Content MD5"]) == 32

    def test_sha1_is_40_hex_chars(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File SHA1"]) == 40
        assert len(data["Content SHA1"]) == 40

    def test_sha256_is_64_hex_chars(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        assert len(data["File SHA256"]) == 64
        assert len(data["Content SHA256"]) == 64

    def test_all_hashes_are_lowercase_hex(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        valid_chars = set("0123456789abcdef")
        for key, value in data.items():
            assert set(value) <= valid_chars, f"Hash '{key}' contains non-lowercase-hex chars: {value}"

    def test_file_sha256_matches_direct_hash(self):
        """File hash must match independently computed hash of the raw file bytes."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.sha256(file_bytes).hexdigest()
        assert result["Digests"]["Data"]["File SHA256"] == expected

    def test_file_md5_matches_direct_hash(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.md5(file_bytes).hexdigest()
        assert result["Digests"]["Data"]["File MD5"] == expected

    def test_file_sha1_matches_direct_hash(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.sha1(file_bytes).hexdigest()
        assert result["Digests"]["Data"]["File SHA1"] == expected

    def test_content_sha256_matches_direct_hash(self):
        """Content hash must match hashlib computed from mail_data string."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.sha256(mail_data.encode("utf-8")).hexdigest()
        assert result["Digests"]["Data"]["Content SHA256"] == expected

    def test_content_md5_matches_direct_hash(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.md5(mail_data.encode("utf-8")).hexdigest()
        assert result["Digests"]["Data"]["Content MD5"] == expected

    def test_content_sha1_matches_direct_hash(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.sha1(mail_data.encode("utf-8")).hexdigest()
        assert result["Digests"]["Data"]["Content SHA1"] == expected

    def test_file_hash_and_content_hash_are_independent_computations(self):
        """File hash: raw bytes. Content hash: mail_data re-encoded to UTF-8.
        Both must be independently verifiable."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        assert data["File SHA256"]    == hashlib.sha256(file_bytes).hexdigest()
        assert data["Content SHA256"] == hashlib.sha256(mail_data.encode("utf-8")).hexdigest()

    def test_all_six_hashes_present_on_different_fixture(self):
        """Six hashes must be produced for any valid .eml, not just basic.eml."""
        file_bytes = load_fixture_bytes("spoofed.eml")
        mail_data  = load_fixture("spoofed.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        data = result["Digests"]["Data"]

        for key in ["File MD5", "File SHA1", "File SHA256",
                    "Content MD5", "Content SHA1", "Content SHA256"]:
            assert key in data

    def test_hashes_correct_on_different_fixture(self):
        """File SHA256 must match direct computation for a second fixture."""
        file_bytes = load_fixture_bytes("spoofed.eml")
        mail_data  = load_fixture("spoofed.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        assert result["Digests"]["Data"]["File SHA256"] == hashlib.sha256(file_bytes).hexdigest()

    def test_different_files_produce_different_hashes(self):
        """Two distinct .eml files must produce different hash values."""
        bytes1 = load_fixture_bytes("basic.eml")
        bytes2 = load_fixture_bytes("spoofed.eml")
        mail1  = load_fixture("basic.eml")
        mail2  = load_fixture("spoofed.eml")

        result1 = get_digests(mail1, bytes1, investigation=False)
        result2 = get_digests(mail2, bytes2, investigation=False)

        assert result1["Digests"]["Data"]["File SHA256"] != result2["Digests"]["Data"]["File SHA256"]
        assert result1["Digests"]["Data"]["Content SHA256"] != result2["Digests"]["Data"]["Content SHA256"]

    def test_hashes_are_deterministic(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result1 = get_digests(mail_data, file_bytes, investigation=False)
        result2 = get_digests(mail_data, file_bytes, investigation=False)

        assert result1["Digests"]["Data"] == result2["Digests"]["Data"]

    def test_returns_correct_structure(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        assert "Digests" in result
        assert "Data" in result["Digests"]
        assert "Investigation" in result["Digests"]


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)
        assert result["Digests"]["Investigation"] == {}

    def test_investigation_generates_virustotal_links_for_all_hashes(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=True)
        inv = result["Digests"]["Investigation"]

        for key in ["File MD5", "File SHA1", "File SHA256",
                    "Content MD5", "Content SHA1", "Content SHA256"]:
            assert key in inv
            assert "Virustotal" in inv[key]
            assert "virustotal.com" in inv[key]["Virustotal"]

    def test_investigation_links_contain_actual_hash_value(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=True)

        for key in ["File MD5", "File SHA1", "File SHA256",
                    "Content MD5", "Content SHA1", "Content SHA256"]:
            hash_val = result["Digests"]["Data"][key]
            vt_link  = result["Digests"]["Investigation"][key]["Virustotal"]
            assert hash_val in vt_link, f"{key} hash value not found in VT link"

    def test_investigation_count_matches_data_count(self):
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=True)
        assert len(result["Digests"]["Data"]) == len(result["Digests"]["Investigation"])


class TestRegressionBug31:
    """Regression tests for Bug #31 — file opened twice with inconsistent modes."""

    def test_file_opened_once_file_hash_matches_raw_bytes(self):
        """File hash must match bytes read directly — no double-open, no mode mismatch."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        # Verify against the exact bytes passed in — not a re-read of the file
        assert result["Digests"]["Data"]["File SHA256"] == hashlib.sha256(file_bytes).hexdigest()
        assert result["Digests"]["Data"]["File MD5"]    == hashlib.md5(file_bytes).hexdigest()

    def test_no_filename_parameter_in_get_digests(self):
        """get_digests must accept bytes, not a filename string."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = load_fixture("basic.eml")

        # Passing bytes must work; passing a string path must raise TypeError
        result = get_digests(mail_data, file_bytes, investigation=False)
        assert result is not None

        with pytest.raises((TypeError, AttributeError)):
            get_digests(mail_data, fixture_path("basic.eml"), investigation=False)

    def test_content_hash_consistent_with_decoded_string(self):
        """Content hash is from mail_data (decoded string), not raw bytes."""
        file_bytes = load_fixture_bytes("basic.eml")
        mail_data  = file_bytes.decode("utf-8", errors="replace").rstrip()
        result = get_digests(mail_data, file_bytes, investigation=False)

        expected = hashlib.sha256(mail_data.encode("utf-8")).hexdigest()
        assert result["Digests"]["Data"]["Content SHA256"] == expected
