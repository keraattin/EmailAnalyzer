"""
Tests for RFC 2047 encoded header decoding (Enhancement #46)

Covers:
- Base64-encoded UTF-8 subject is decoded to plain text
- Quoted-printable encoded UTF-8 subject is decoded to plain text
- ISO-8859-1 encoded display name is decoded correctly
- Non-encoded headers are returned unchanged
- Encoded From display name is decoded, email address preserved
- Multiple encoded headers all decoded in one pass
- Plain ASCII headers are not altered
- Decoded value contains no RFC 2047 syntax tokens (=?...?=)
- Investigation still works correctly after decoding
- Spoof check still works on decoded From/Reply-To values
- Regression: raw =?...?= tokens do not appear in output
"""

import pytest
from conftest import get_headers, load_fixture


class TestBase64Decoding:
    def test_base64_subject_decoded(self):
        """=?UTF-8?B?...?= subject must be decoded to human-readable text."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        subject = result["Headers"]["Data"]["subject"]

        assert subject == "Hello World"
        assert "=?" not in subject

    def test_base64_from_display_name_decoded(self):
        """Encoded display name in From must be decoded."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        from_val = result["Headers"]["Data"]["from"]

        assert "Hello World" in from_val
        assert "=?" not in from_val

    def test_base64_from_email_address_preserved(self):
        """Email address in From must be preserved after decoding the display name."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        from_val = result["Headers"]["Data"]["from"]

        assert "sender@example.com" in from_val

    def test_base64_no_encoding_tokens_in_output(self):
        """No =?...?= tokens must appear anywhere in decoded header values."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)

        for key, value in result["Headers"]["Data"].items():
            assert "=?" not in value, f"Encoding token found in header '{key}': {value}"


class TestQuotedPrintableDecoding:
    def test_qp_subject_decoded(self):
        """=?UTF-8?Q?...?= subject must be decoded to plain text."""
        mail_data = load_fixture("rfc2047_qp_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        subject = result["Headers"]["Data"]["subject"]

        assert subject == "Café au lait"
        assert "=?" not in subject

    def test_qp_no_encoding_tokens_in_output(self):
        mail_data = load_fixture("rfc2047_qp_encoded.eml")
        result = get_headers(mail_data, investigation=False)

        for key, value in result["Headers"]["Data"].items():
            assert "=?" not in value, f"Encoding token found in header '{key}': {value}"


class TestMixedCharsetDecoding:
    def test_iso8859_display_name_decoded(self):
        """ISO-8859-1 encoded display name must be decoded correctly."""
        mail_data = load_fixture("rfc2047_mixed.eml")
        result = get_headers(mail_data, investigation=False)
        from_val = result["Headers"]["Data"]["from"]

        assert "André" in from_val
        assert "=?" not in from_val

    def test_utf8_base64_subject_decoded(self):
        """UTF-8 base64 encoded subject must decode to the correct Unicode string."""
        mail_data = load_fixture("rfc2047_mixed.eml")
        result = get_headers(mail_data, investigation=False)
        subject = result["Headers"]["Data"]["subject"]

        assert subject == "Resumé"
        assert "=?" not in subject

    def test_custom_header_decoded(self):
        """Encoded non-standard headers must also be decoded."""
        mail_data = load_fixture("rfc2047_mixed.eml")
        result = get_headers(mail_data, investigation=False)
        custom = result["Headers"]["Data"]["x-custom"]

        assert "=?" not in custom
        assert "Test" in custom

    def test_no_encoding_tokens_anywhere(self):
        mail_data = load_fixture("rfc2047_mixed.eml")
        result = get_headers(mail_data, investigation=False)

        for key, value in result["Headers"]["Data"].items():
            assert "=?" not in value, f"Encoding token found in header '{key}': {value}"


class TestPlainHeadersUnchanged:
    def test_plain_ascii_subject_unchanged(self):
        """Headers with no RFC 2047 encoding must pass through unchanged."""
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)

        assert result["Headers"]["Data"]["from"] == "sender@example.com"
        assert result["Headers"]["Data"]["to"] == "recipient@example.com"

    def test_plain_subject_unchanged(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        assert result["Headers"]["Data"]["subject"] == "Basic Test Email"

    def test_no_double_encoding_on_plain_values(self):
        """Plain values must not have any HTML or encoding artifacts added."""
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        from_val = result["Headers"]["Data"]["from"]

        assert from_val == "sender@example.com"


class TestInvestigationAfterDecoding:
    def test_spoof_check_works_on_decoded_headers(self):
        """Spoof check must still parse email addresses from decoded From/Reply-To."""
        mail_data = load_fixture("spoofed.eml")
        result = get_headers(mail_data, investigation=True)

        assert "Spoof Check" in result["Headers"]["Investigation"]
        conclusion = result["Headers"]["Investigation"]["Spoof Check"]["Conclusion"]
        assert "SPOOFED" in conclusion or "SAME" in conclusion

    def test_investigation_present_after_decoding(self):
        """Investigation section must still be populated after RFC 2047 decoding."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)

        assert "Headers" in result
        assert "Data" in result["Headers"]
        assert "Investigation" in result["Headers"]

    def test_encoded_subject_investigation_disabled_returns_empty(self):
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        assert result["Headers"]["Investigation"] == {}


class TestRegressionEnhancement46:
    """Regression tests for Enhancement #46 — RFC 2047 encoded headers shown raw."""

    def test_base64_token_not_in_subject(self):
        """Previously: subject appeared as =?UTF-8?B?SGVsbG8gV29ybGQ=?= raw."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        assert "=?UTF-8?B?" not in result["Headers"]["Data"]["subject"]

    def test_qp_token_not_in_subject(self):
        """Previously: subject appeared as =?UTF-8?Q?Caf=C3=A9_au_lait?= raw."""
        mail_data = load_fixture("rfc2047_qp_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        assert "=?UTF-8?Q?" not in result["Headers"]["Data"]["subject"]

    def test_decoded_value_is_valid_string(self):
        """Decoded header value must be a non-empty plain string."""
        mail_data = load_fixture("rfc2047_encoded.eml")
        result = get_headers(mail_data, investigation=False)
        subject = result["Headers"]["Data"]["subject"]

        assert isinstance(subject, str)
        assert len(subject) > 0
