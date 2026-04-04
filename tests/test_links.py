"""
Tests for get_links()

Covers:
- Basic link extraction from HTML email
- Single link email
- No links returns empty result
- Empty href filtered out
- Duplicate links deduplicated (2x and 3x)
- Links indexed from 1, sequential
- URLs with query parameters preserved
- URLs with fragments preserved
- Investigation mode: VirusTotal and URLScan links
- Investigation mode: exact VT and URLScan URL format
- Investigation mode: https:// protocol stripped
- Investigation mode: http:// protocol stripped
- Investigation mode: count matches data count
- Investigation mode: no links = empty investigation
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

    def test_links_are_sequential_integers(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        keys = list(result["Links"]["Data"].keys())
        for i, key in enumerate(keys, start=1):
            assert key == str(i)

    def test_duplicate_links_deduplicated(self):
        """Same URL appearing twice must appear only once in results."""
        mail_data = load_fixture("http_links.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())
        assert len(values) == len(set(values))

    def test_empty_href_filtered_out(self):
        """href="" must not appear in the extracted links."""
        mail_data = load_fixture("http_links.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())
        assert "" not in values

    def test_http_links_extracted(self):
        """http:// links (not just https://) must be extracted."""
        mail_data = load_fixture("http_links.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())
        assert any("http://insecure-site.com" in v for v in values)

    def test_returns_correct_structure(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        assert "Links" in result
        assert "Data" in result["Links"]
        assert "Investigation" in result["Links"]


class TestEdgeCaseLinks:
    def test_single_link_extracted(self):
        mail_data = load_fixture("single_link.eml")
        result = get_links(mail_data, investigation=False)
        data = result["Links"]["Data"]

        assert len(data) == 1
        assert data["1"] == "https://only-one-link.com/verify"

    def test_url_with_query_params_preserved(self):
        """Query string must be preserved exactly as-is in the extracted URL."""
        mail_data = load_fixture("links_with_params.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())

        assert any("utm_source=email" in v for v in values)
        assert any("utm_campaign=promo" in v for v in values)
        assert any("id=123" in v for v in values)

    def test_url_with_fragment_preserved(self):
        """URL fragment (#section) must be preserved in the extracted URL."""
        mail_data = load_fixture("links_with_params.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())

        assert any("#section2" in v for v in values)

    def test_triple_duplicate_deduplicated_to_one(self):
        """URL appearing 3 times (once organic + 2 duplicates) must appear only once."""
        mail_data = load_fixture("links_with_params.eml")
        result = get_links(mail_data, investigation=False)
        values = list(result["Links"]["Data"].values())

        param_url_count = sum(1 for v in values if "utm_source=email" in v)
        assert param_url_count == 1

    def test_params_email_has_two_unique_links(self):
        """links_with_params.eml has 3 hrefs but 2 unique — result must be 2."""
        mail_data = load_fixture("links_with_params.eml")
        result = get_links(mail_data, investigation=False)
        assert len(result["Links"]["Data"]) == 2


class TestInvestigationMode:
    def test_investigation_disabled_returns_empty(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        assert result["Links"]["Investigation"] == {}

    def test_no_links_investigation_is_empty(self):
        mail_data = load_fixture("no_links.eml")
        result = get_links(mail_data, investigation=True)
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

    def test_investigation_count_matches_data_count(self):
        """Every extracted link must have a corresponding investigation entry."""
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        assert len(result["Links"]["Data"]) == len(result["Links"]["Investigation"])

    def test_https_protocol_stripped_in_investigation(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        for entry in inv.values():
            assert "https://https://" not in entry["Virustotal"]

    def test_http_protocol_stripped_in_investigation(self):
        mail_data = load_fixture("http_links.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        for entry in inv.values():
            assert "http://http://" not in entry["Virustotal"]

    def test_virustotal_url_exact_format(self):
        """VT investigation URL must be virustotal.com/gui/search/{domain}."""
        mail_data = load_fixture("single_link.eml")
        result = get_links(mail_data, investigation=True)
        vt_url = result["Links"]["Investigation"]["1"]["Virustotal"]

        assert vt_url == "https://www.virustotal.com/gui/search/only-one-link.com/verify"

    def test_urlscan_url_exact_format(self):
        """URLScan investigation URL must be urlscan.io/search/#{domain}."""
        mail_data = load_fixture("single_link.eml")
        result = get_links(mail_data, investigation=True)
        urlscan_url = result["Links"]["Investigation"]["1"]["Urlscan"]

        assert urlscan_url == "https://urlscan.io/search/#only-one-link.com/verify"

    def test_investigation_urlscan_link_contains_domain(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        for entry in inv.values():
            urlscan = entry["Urlscan"]
            # Must contain the domain, not just the base urlscan URL
            assert urlscan != "https://urlscan.io/search/#"


class TestRegressionBug25:
    """Regression tests for Bug #25 — TypeError in quoted-printable decode."""

    def test_qp_email_does_not_raise_typeerror(self):
        """Previously: quopri.decodestring(str) raised TypeError."""
        mail_data = load_fixture("quoted_printable.eml")
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
        assert len(result["Links"]["Data"]) == 2

    def test_qp_email_investigation_works(self):
        """Investigation mode must also work on QP-decoded links."""
        mail_data = load_fixture("quoted_printable.eml")
        result = get_links(mail_data, investigation=True)
        inv = result["Links"]["Investigation"]

        assert len(inv) >= 2
        for entry in inv.values():
            assert "Virustotal" in entry
            assert "Urlscan" in entry
