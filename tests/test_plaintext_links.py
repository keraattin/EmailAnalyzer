"""
Tests for plain-text body URL extraction (Enhancement #68)

Covers:
- Bare URLs in plain-text-only emails are extracted
- http:// and https:// both matched in plain text
- Multiple plain-text URLs extracted and indexed
- Trailing punctuation stripped from plain-text URLs
- multipart/alternative: HTML href links + plain-text-only URLs both extracted
- Shared URL across HTML and plain text deduplicated (appears once)
- HTML-only link still extracted when plain text has no unique URLs
- Plain-text-only URL appears after HTML links in output order
- Investigation mode works on plain-text extracted URLs
- Defang flag applies to plain-text extracted URLs
"""

import pytest
from conftest import get_links, load_fixture


class TestPlaintextLinkExtraction:
    def test_bare_https_url_extracted_from_plaintext(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        assert any("phishing-site.com" in v for v in values)

    def test_bare_http_url_extracted_from_plaintext(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        assert any("http://backup-site.net" in v for v in values)

    def test_multiple_plaintext_urls_all_extracted(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False)
        assert len(result["Links"]["Data"]) == 3

    def test_plaintext_urls_indexed_from_one(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False)
        keys = list(result["Links"]["Data"].keys())
        assert keys[0] == "1"

    def test_plaintext_url_trailing_period_stripped(self):
        """URLs followed by a period (end of sentence) must not include the period."""
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        assert not any(v.endswith(".") for v in values)

    def test_no_links_plaintext_returns_empty(self):
        result = get_links(load_fixture("no_links.eml"), investigation=False)
        assert result["Links"]["Data"] == {}


class TestMultipartAltLinkExtraction:
    def test_html_href_links_extracted(self):
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        assert any("html-only.com" in v for v in values)

    def test_plaintext_only_url_extracted(self):
        """URL present only in plain-text part must be extracted."""
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        assert any("plaintext-only.com" in v for v in values)

    def test_shared_url_deduplicated(self):
        """URL appearing in both HTML and plain text must appear only once."""
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=False)
        values = list(result["Links"]["Data"].values())
        phishing_count = sum(1 for v in values if "phishing-site.com" in v)
        assert phishing_count == 1

    def test_total_unique_links_count(self):
        """Three unique URLs across both parts must produce three entries."""
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=False)
        assert len(result["Links"]["Data"]) == 3

    def test_html_links_appear_before_plaintext_only_links(self):
        """HTML href links take priority and appear first in the output."""
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=False)
        data = result["Links"]["Data"]
        # phishing-site.com is in both — must be at index 1 (from HTML)
        assert "phishing-site.com" in data["1"]
        # plaintext-only.com is only in plain text — must appear last
        assert "plaintext-only.com" in data["3"]


class TestPlaintextInvestigation:
    def test_investigation_works_on_plaintext_urls(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=True)
        inv = result["Links"]["Investigation"]
        assert len(inv) == 3
        for entry in inv.values():
            assert "Virustotal" in entry
            assert "Urlscan" in entry

    def test_investigation_count_matches_data_count(self):
        result = get_links(load_fixture("multipart_alt_links.eml"), investigation=True)
        assert len(result["Links"]["Data"]) == len(result["Links"]["Investigation"])


class TestPlaintextDefang:
    def test_defang_applies_to_plaintext_urls(self):
        result = get_links(load_fixture("plaintext_links.eml"), investigation=False, defang=True)
        values = list(result["Links"]["Data"].values())
        assert all(v.startswith("hxxp") for v in values)
        assert all("[.]" in v for v in values)
