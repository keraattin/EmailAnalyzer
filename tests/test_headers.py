"""
Tests for get_headers()

Covers:
- General header extraction
- Investigation mode (X-Sender-IP links)
- Spoof detection: spoofed email
- Spoof detection: not spoofed email
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
    def test_x_sender_ip_generates_investigation_links(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]

        assert "X-Sender-Ip" in inv
        assert "192.168.1.100" in inv["X-Sender-Ip"]["Virustotal"]
        assert "192.168.1.100" in inv["X-Sender-Ip"]["Abuseipdb"]

    def test_no_x_sender_ip_skips_investigation(self):
        mail_data = load_fixture("spoofed.eml")
        result = get_headers(mail_data, investigation=True)
        assert "X-Sender-Ip" not in result["Headers"]["Investigation"]


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

    def test_no_reply_to_skips_spoof_check(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=True)
        assert "Spoof Check" not in result["Headers"]["Investigation"]


class TestRegressionBug26:
    """Regression tests for Bug #26 — IndexError on display-name-only From header."""

    def test_display_name_only_from_does_not_crash(self):
        """Previously raised IndexError: list index out of range."""
        mail_data = load_fixture("display_name_only.eml")
        # Must not raise any exception
        result = get_headers(mail_data, investigation=True)
        assert result is not None

    def test_display_name_only_returns_graceful_conclusion(self):
        mail_data = load_fixture("display_name_only.eml")
        result = get_headers(mail_data, investigation=True)
        spoof = result["Headers"]["Investigation"]["Spoof Check"]
        assert "Could not parse" in spoof["Conclusion"]
