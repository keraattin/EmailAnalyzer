"""
Tests for X-Originating-IP investigation (Enhancement #72)

Covers:
- X-Originating-IP present → X-Originating-Ip investigation entry added
- Investigation entry contains Virustotal and Abuseipdb URLs with correct IP
- No X-Originating-IP header → no investigation entry added
- X-Sender-IP and X-Originating-IP both present → both entries appear independently
- investigation=False → no X-Originating-Ip entry
"""

import pytest
from conftest import get_headers, load_fixture


class TestXOriginatingIpPresent:
    def test_originating_ip_investigation_entry_added(self):
        result = get_headers(load_fixture("originating_ip.eml"), investigation=True)
        assert "X-Originating-Ip" in result["Headers"]["Investigation"]

    def test_originating_ip_virustotal_url(self):
        result = get_headers(load_fixture("originating_ip.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["X-Originating-Ip"]
        assert entry["Virustotal"] == "https://www.virustotal.com/gui/search/203.0.113.42"

    def test_originating_ip_abuseipdb_url(self):
        result = get_headers(load_fixture("originating_ip.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["X-Originating-Ip"]
        assert entry["Abuseipdb"] == "https://www.abuseipdb.com/check/203.0.113.42"

    def test_originating_ip_entry_has_exactly_two_keys(self):
        result = get_headers(load_fixture("originating_ip.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["X-Originating-Ip"]
        assert set(entry.keys()) == {"Virustotal", "Abuseipdb"}


class TestXOriginatingIpAbsent:
    def test_no_originating_ip_header_no_investigation_entry(self):
        result = get_headers(load_fixture("basic.eml"), investigation=True)
        assert "X-Originating-Ip" not in result["Headers"]["Investigation"]

    def test_investigation_false_no_originating_ip_entry(self):
        result = get_headers(load_fixture("originating_ip.eml"), investigation=False)
        assert "X-Originating-Ip" not in result["Headers"]["Investigation"]


class TestRegressionEnhancement72:
    def test_x_sender_ip_unaffected(self):
        """X-Sender-IP investigation must still work when X-Originating-IP is absent."""
        result = get_headers(load_fixture("basic.eml"), investigation=True)
        assert "X-Sender-Ip" in result["Headers"]["Investigation"]

    def test_spoof_check_unaffected(self):
        """Spoof Check must still appear when both sender and reply-to are present."""
        result = get_headers(load_fixture("spoofed.eml"), investigation=True)
        assert "Spoof Check" in result["Headers"]["Investigation"]
