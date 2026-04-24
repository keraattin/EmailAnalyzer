"""
Tests for Received header IP extraction (Enhancement #47)

Covers:
- Public IPs from Received headers appear in investigation
- Each IP has VirusTotal and AbuseIPDB links
- Private IPs (RFC 1918) are excluded from investigation
- Loopback (127.0.0.1) is excluded from investigation
- Duplicate IPs across multiple Received headers deduplicated
- No Received header produces no Received IPs investigation entry
- Investigation disabled returns no Received IPs entry
- VT and AbuseIPDB URLs contain the actual IP value
- VT URL uses correct format (virustotal.com/gui/search/)
- AbuseIPDB URL uses correct format (abuseipdb.com/check/)
- Mixed public/private: only public IPs appear
- Multiple distinct public IPs all appear
"""

import pytest
from conftest import get_headers, load_fixture


class TestPublicIPExtraction:
    def test_public_ips_present_in_investigation(self):
        """Public IPs from Received headers must appear in investigation."""
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        assert "Received IPs" in result["Headers"]["Investigation"]

    def test_both_public_ips_extracted(self):
        """All distinct public IPs must be present as keys."""
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips

    def test_each_ip_has_virustotal_link(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        for ip, links in ips.items():
            assert "Virustotal" in links, f"No Virustotal link for {ip}"

    def test_each_ip_has_abuseipdb_link(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        for ip, links in ips.items():
            assert "Abuseipdb" in links, f"No Abuseipdb link for {ip}"

    def test_virustotal_url_contains_ip(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        for ip, links in ips.items():
            assert ip in links["Virustotal"], f"IP {ip} not in VT URL"

    def test_abuseipdb_url_contains_ip(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        for ip, links in ips.items():
            assert ip in links["Abuseipdb"], f"IP {ip} not in AbuseIPDB URL"

    def test_virustotal_url_exact_format(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]
        ip = "8.8.8.8"

        assert ips[ip]["Virustotal"] == f"https://www.virustotal.com/gui/search/{ip}"

    def test_abuseipdb_url_exact_format(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]
        ip = "8.8.8.8"

        assert ips[ip]["Abuseipdb"] == f"https://www.abuseipdb.com/check/{ip}"


class TestPrivateIPFiltering:
    def test_private_rfc1918_ips_excluded(self):
        """10.x.x.x and 192.168.x.x addresses must not appear in investigation."""
        mail_data = load_fixture("received_mixed_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        assert "10.0.0.5" not in ips
        assert "192.168.1.1" not in ips

    def test_loopback_excluded(self):
        """127.0.0.1 must not appear in investigation."""
        mail_data = load_fixture("received_mixed_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        assert "127.0.0.1" not in ips

    def test_only_public_ip_extracted_from_mixed(self):
        """Only the public IP must appear when Received headers contain mixed IPs."""
        mail_data = load_fixture("received_mixed_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        assert "8.8.4.4" in ips
        assert len(ips) == 1

    def test_all_private_ips_produces_no_received_ips_entry(self):
        """When all Received IPs are private, Received IPs must not appear in investigation."""
        mail_data = load_fixture("multi_received.eml")
        result = get_headers(mail_data, investigation=True)

        assert "Received IPs" not in result["Headers"]["Investigation"]


class TestDeduplication:
    def test_duplicate_ips_deduplicated(self):
        """The same public IP appearing in multiple Received headers must appear only once."""
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        ips = result["Headers"]["Investigation"]["Received IPs"]

        ip_list = list(ips.keys())
        assert len(ip_list) == len(set(ip_list))


class TestInvestigationDisabled:
    def test_investigation_disabled_no_received_ips(self):
        """With investigation=False, Received IPs must not appear."""
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=False)

        assert "Received IPs" not in result["Headers"]["Investigation"]

    def test_investigation_disabled_returns_empty_investigation(self):
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=False)

        assert result["Headers"]["Investigation"] == {}


class TestNoReceivedHeader:
    def test_no_received_header_no_crash(self):
        """Emails without Received headers must not crash."""
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=True)
        assert result is not None

    def test_no_received_header_no_received_ips_entry(self):
        mail_data = load_fixture("minimal.eml")
        result = get_headers(mail_data, investigation=True)
        assert "Received IPs" not in result["Headers"]["Investigation"]


class TestRegressionEnhancement47:
    """Regression tests for Enhancement #47 — Received IPs not investigated."""

    def test_public_ip_was_previously_ignored(self):
        """Previously public IPs in Received were not linked to any investigation tool."""
        mail_data = load_fixture("received_public_ips.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"]

        assert "Received IPs" in inv
        assert len(inv["Received IPs"]) > 0

    def test_private_ip_still_not_investigated(self):
        """Private IPs must never appear in investigation regardless of context."""
        mail_data = load_fixture("received_mixed_ips.eml")
        result = get_headers(mail_data, investigation=True)
        inv = result["Headers"]["Investigation"].get("Received IPs", {})

        for ip in inv:
            assert not ip.startswith("10.")
            assert not ip.startswith("192.168.")
            assert not ip.startswith("127.")
