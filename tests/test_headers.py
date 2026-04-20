"""
Tests for get_headers()

Covers:
- General header extraction
- Header key normalization (lowercase)
- Tab/newline stripping from values
- Multiple Received headers joined
- Minimal email (only mandatory headers, no optional fields)
- Investigation mode (X-Sender-IP links)
- Investigation mode: exact VT and AbuseIPDB URL format
- Investigation mode: only relevant keys produced
- Spoof detection: spoofed email
- Spoof detection: not spoofed email
- Spoof detection: From with display name + angle bracket email
- Spoof detection: no From header skips check
- Regression #26: display-name-only From header no longer crashes
"""

import pytest
from conftest import get_headers, load_fixture


class TestHeaderExtraction:
    def test_basic_headers_extracted(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        assert data["from"] == "sender@example.com"
        assert data["to"] == "recipient@example.com"
        assert data["subject"] == "Basic Test Email"
        assert "mime-version" in data
        assert "content-type" in data

    def test_header_keys_are_lowercase(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        for key in data:
            assert key == key.lower(), f"Header key '{key}' is not lowercase"

    def test_tabs_stripped_from_header_values(self):
        mail_data = load_fixture("headers_with_tabs.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        for key, value in data.items():
            assert "\t" not in value, f"Tab found in header '{key}': {repr(value)}"

    def test_newlines_stripped_from_header_values(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        for key, value in data.items():
            assert "\n" not in value, f"Newline found in header '{key}': {repr(value)}"

    def test_multiple_received_headers_joined(self):
        mail_data = load_fixture("multi_received.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        assert "received" in data
        # All 3 relay hops must appear in the single joined value
        assert "mail1.example.com" in data["received"]
        assert "mail2.example.com" in data["received"]
        assert "mail3.example.com" in data["received"]

    def test_investigation_not_run_when_disabled(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        assert result["Headers"]["Investigation"] == {}

    def test_returns_correct_structure(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        assert "Headers" in result
        assert "Data" in result["Headers"]
        assert "Investigation" in result["Headers"]


class TestInvestigationMode:
    def test_x_sender_ip_generates_virustotal_link(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]

        assert "X-Sender-Ip" in inv
        assert "192.168.1.100" in inv["X-Sender-Ip"]["Virustotal"]

    def test_x_sender_ip_generates_abuseipdb_link(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]

        assert "192.168.1.100" in inv["X-Sender-Ip"]["Abuseipdb"]
        assert "abuseipdb.com" in inv["X-Sender-Ip"]["Abuseipdb"]

    def test_no_x_sender_ip_skips_investigation(self):
        mail_data = load_fixture("spoofed.eml")
        result = get_headers(mail_data, investigation=True)
        assert "X-Sender-Ip" not in result["Headers"]["Investigation"]

    def test_investigation_structure_has_both_links(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]["X-Sender-Ip"]

        assert "Virustotal" in inv
        assert "Abuseipdb" in inv


class TestSpoofDetection:
    def test_spoofed_email_detected(self):
        mail_data = load_fixture("spoofed.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]

        assert spoof["From"] == "legit@bank.com"
        assert spoof["Reply-To"] == "attacker@evil.com"
        assert "SPOOFED" in spoof["Conclusion"]

    def test_not_spoofed_email(self):
        mail_data = load_fixture("not_spoofed.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]

        assert spoof["From"] == "sender@example.com"
        assert spoof["Reply-To"] == "sender@example.com"
        assert "SAME" in spoof["Conclusion"]

    def test_spoof_check_has_required_fields(self):
        mail_data = load_fixture("spoofed.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]

        assert "From" in spoof
        assert "Reply-To" in spoof
        assert "Conclusion" in spoof

    def test_no_reply_to_skips_spoof_check(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        assert "Spoof Check" not in result["Headers"]["Investigation"]

    def test_from_with_display_name_extracts_email_correctly(self):
        """From: "Bank Admin" <admin@bank.com> — spoof check should use admin@bank.com."""
        mail_data = load_fixture("display_name_email_from.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]

        assert spoof["From"] == "admin@bank.com"
        assert spoof["Reply-To"] == "attacker@evil.com"
        assert "SPOOFED" in spoof["Conclusion"]

    def test_no_from_header_skips_spoof_check(self):
        """If From header is absent, spoof check must be skipped entirely."""
        mail_data = load_fixture("display_name_only.eml")
        result = get_headers(mail_data, investigation=False)
        # investigation=False — spoof check section should not exist
        assert "Spoof Check" not in result["Headers"]["Investigation"]


class TestMinimalEmail:
    def test_minimal_email_has_correct_structure(self):
        """Email with only From/To/Subject must still return valid structure."""
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=False)

        assert "Headers" in result
        assert "Data" in result["Headers"]
        assert result["Headers"]["Data"]["from"] == "sender@example.com"
        assert result["Headers"]["Data"]["to"] == "recipient@example.com"
        assert result["Headers"]["Data"]["subject"] == "Minimal Email"

    def test_minimal_email_no_spoof_or_ip_investigation(self):
        """No X-Sender-IP and no Reply-To → Spoof Check and X-Sender-Ip must be absent."""
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]
        assert "Spoof Check" not in inv
        assert "X-Sender-Ip" not in inv

    def test_minimal_email_missing_optional_headers(self):
        """Optional headers like mime-version, content-type must not appear."""
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=False)
        data = result["Headers"]["Data"]

        assert "mime-version" not in data
        assert "content-type" not in data
        assert "x-sender-ip" not in data


class TestInvestigationUrlFormats:
    def test_virustotal_url_uses_gui_search_format(self):
        """VT URL must follow the /gui/search/{ip} pattern."""
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        vt_url = result["Headers"]["Investigation"]["X-Sender-Ip"]["Virustotal"]

        assert vt_url == "https://www.virustotal.com/gui/search/192.168.1.100"

    def test_abuseipdb_url_uses_check_format(self):
        """AbuseIPDB URL must follow the /check/{ip} pattern."""
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        abuse_url = result["Headers"]["Investigation"]["X-Sender-Ip"]["Abuseipdb"]

        assert abuse_url == "https://www.abuseipdb.com/check/192.168.1.100"

    def test_investigation_only_contains_relevant_keys(self):
        """Investigation must not produce keys for headers that don't exist."""
        mail_data = load_fixture("spoofed.eml")  # no X-Sender-IP
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]

        assert "X-Sender-Ip" not in inv
        assert "Spoof Check" in inv

    def test_investigation_with_no_investigatable_headers_has_no_spoof_or_ip(self):
        """No X-Sender-IP and no Reply-To → Spoof Check and X-Sender-Ip must be absent."""
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]
        assert "Spoof Check" not in inv
        assert "X-Sender-Ip" not in inv


class TestRegressionBug26:
    """Regression tests for Bug #26 — IndexError on display-name-only From header."""

    def test_display_name_only_from_does_not_crash(self):
        """Previously raised IndexError: list index out of range."""
        mail_data = load_fixture("display_name_only.eml")
        result = get_headers(mail_data, investigation=True)
        assert result is not None

    def test_display_name_only_returns_graceful_conclusion(self):
        mail_data = load_fixture("display_name_only.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]
        assert "Could not parse" in spoof["Conclusion"]

    def test_display_name_only_preserves_raw_values_in_output(self):
        """Raw header values should still be reported even when unparseable."""
        mail_data = load_fixture("display_name_only.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]

        assert "Reply-To" in spoof
        assert "From" in spoof
        assert spoof["Reply-To"] != ""
        assert spoof["From"] != ""
