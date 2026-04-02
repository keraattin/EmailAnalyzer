"""
Tests for get_links()

Covers:
- Basic link extraction from HTML email
- No links returns empty result
- Investigation mode generates correct URLs
- Duplicate links are deduplicated
- Regression #25: quoted-printable decode no longer raises TypeError
"""

import pytest
from conftest import get_links, load_fixture


class TestLinkExtraction:
    def test_extracts_links_from_html_body(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        data = result["Links"]["Data"]

        assert len(data) == 2
        assert any("example.com/page" in v for v in data.values())
        assert any("another-site.com" in v for v in data.values())

    def test_no_links_returns_empty(self):
        mail_data = load_fixture("no_links.eml")
        result = get_links(mail_data, investigation=False)
        assert result["Links"]["Data"] == {}

    def test_links_indexed_from_one(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        keys = list(result["Links"]["Data"].keys())
        assert keys[0] == "1"

    def test_duplicate_links_deduplicated(self):
        # basic.eml has 2 distinct links — verify no duplicates
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())
        assert len(values) == len(set(values))

    def test_returns_correct_structure(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        assert "Links" in result
        assert "Data" in result["Links"]
        assert "Investigation" in result["Links"]


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        assert result["Links"]["Investigation"] == {}

    def test_investigation_generates_virustotal_links(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        assert len(inv) > 0
        for entry in inv.values():
            assert "Virustotal" in entry
            assert "virustotal.com" in entry["Virustotal"]

    def test_investigation_generates_urlscan_links(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        for entry in inv.values():
            assert "Urlscan" in entry
            assert "urlscan.io" in entry["Urlscan"]

    def test_investigation_strips_protocol_from_urls(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        for entry in inv.values():
            # VirusTotal search URL should not contain "https://https://"
            assert "https://https://" not in entry["Virustotal"]
            assert "http://http://" not in entry["Virustotal"]


class TestRegressionBug25:
    """Regression tests for Bug #25 — TypeError in quoted-printable decode."""

    def test_qp_email_does_not_raise_typeerror(self):
        """Previously: quopri.decodestring(str) raised TypeError."""
        mail_data = load_fixture("quoted_printable.eml")
        # Must not raise any exception
        result = get_links(mail_data, investigation=False)
        assert result is not None

    def test_qp_email_extracts_links(self):
        """Links inside QP-encoded body must be found."""
        mail_data = load_fixture("quoted_printable.eml")
        result = get_links(mail_data, investigation=False)
        data = result["Links"]["Data"]

        assert len(data) >= 2
        assert any("malicious-site.com" in v for v in data.values())
        assert any("cafe-example.com" in v for v in data.values())

    def test_non_qp_email_not_decoded(self):
        """Emails without QP encoding must not be run through quopri."""
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        # basic.eml has no Content-Transfer-Encoding: quoted-printable
        # links should still be found correctly
        assert len(result["Links"]["Data"]) == 2
