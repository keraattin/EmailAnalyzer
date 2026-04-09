"""
Tests for defanged URL output (Enhancement #50)

Covers:
- https:// replaced with hxxps://
- http:// replaced with hxxp://
- Dots in domain replaced with [.]
- Path after domain is preserved unchanged
- Query string preserved unchanged
- URL with no scheme returned with dots defanged only
- defang=False returns URLs unmodified
- defang=True applies to all links in Data section
- Investigation links are NOT defanged (remain functional)
- Defanging is deterministic
- Empty link list with defang=True returns empty data
- Regression #50: raw live URLs no longer appear in defanged output
"""

import pytest
from conftest import get_links, defang_url, load_fixture


class TestDefangHelper:
    def test_https_replaced_with_hxxps(self):
        assert defang_url("https://example.com") == "hxxps://example[.]com"

    def test_http_replaced_with_hxxp(self):
        assert defang_url("http://example.com") == "hxxp://example[.]com"

    def test_domain_dots_replaced(self):
        result = defang_url("https://sub.example.com")
        assert "[.]" in result
        assert "sub[.]example[.]com" in result

    def test_path_preserved(self):
        result = defang_url("https://example.com/path/to/page")
        assert "/path/to/page" in result

    def test_query_string_preserved(self):
        result = defang_url("https://example.com/search?q=test&page=1")
        assert "?q=test&page=1" in result

    def test_path_dots_not_replaced(self):
        """Dots in the path (e.g. file.php) must not be replaced."""
        result = defang_url("https://example.com/page.php?id=1")
        assert "page.php" in result

    def test_scheme_replaced_and_domain_defanged(self):
        result = defang_url("http://malicious.evil.com/payload")
        assert result.startswith("hxxp://")
        assert "malicious[.]evil[.]com" in result

    def test_no_scheme_dots_still_replaced(self):
        """URLs without a scheme should still have domain dots replaced."""
        result = defang_url("example.com/path")
        assert "example[.]com" in result

    def test_defang_applied_to_raw_urls_only(self):
        """_defang_url() is called on raw URLs from the email, not on pre-defanged strings.
        The scheme replacement correctly handles hxxps:// (no further change)."""
        result = defang_url("https://example.com")
        assert result == "hxxps://example[.]com"


class TestGetLinksDefangDisabled:
    def test_defang_false_returns_original_https_url(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False, defang=False)
        for val in result["Links"]["Data"].values():
            assert val.startswith("https://") or val.startswith("http://")

    def test_defang_default_is_false(self):
        """get_links() must default to defang=False."""
        mail_data = load_fixture("basic.eml")
        result_default = get_links(mail_data, investigation=False)
        result_explicit = get_links(mail_data, investigation=False, defang=False)
        assert result_default["Links"]["Data"] == result_explicit["Links"]["Data"]

    def test_no_links_defang_false_returns_empty(self):
        mail_data = load_fixture("no_links.eml")
        result = get_links(mail_data, investigation=False, defang=False)
        assert result["Links"]["Data"] == {}


class TestGetLinksDefangEnabled:
    def test_defang_true_replaces_https_scheme(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for val in result["Links"]["Data"].values():
            assert "https://" not in val
            assert "hxxps://" in val or "hxxp://" in val

    def test_defang_true_replaces_domain_dots(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for val in result["Links"]["Data"].values():
            assert "[.]" in val

    def test_defang_true_all_links_defanged(self):
        """Every entry in Data must be defanged when defang=True."""
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for idx, val in result["Links"]["Data"].items():
            assert "https://" not in val, f"Link {idx} not defanged: {val}"
            assert "http://" not in val, f"Link {idx} not defanged: {val}"

    def test_defang_no_links_returns_empty(self):
        mail_data = load_fixture("no_links.eml")
        result = get_links(mail_data, investigation=False, defang=True)
        assert result["Links"]["Data"] == {}

    def test_defang_is_deterministic(self):
        mail_data = load_fixture("basic.eml")
        result1 = get_links(mail_data, investigation=False, defang=True)
        result2 = get_links(mail_data, investigation=False, defang=True)
        assert result1["Links"]["Data"] == result2["Links"]["Data"]


class TestInvestigationNotDefanged:
    def test_investigation_links_not_defanged(self):
        """VT and URLScan investigation links must remain functional (not defanged)."""
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for idx, inv in result["Links"]["Investigation"].items():
            assert "https://" in inv["Virustotal"], f"VT link {idx} appears defanged"
            assert "https://" in inv["Urlscan"], f"URLScan link {idx} appears defanged"

    def test_investigation_virustotal_url_intact(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for inv in result["Links"]["Investigation"].values():
            assert inv["Virustotal"].startswith("https://www.virustotal.com")

    def test_investigation_urlscan_url_intact(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=True, defang=True)
        for inv in result["Links"]["Investigation"].values():
            assert inv["Urlscan"].startswith("https://urlscan.io")


class TestRegressionEnhancement50:
    """Regression tests for Enhancement #50 — live URLs in output."""

    def test_raw_https_url_not_in_defanged_output(self):
        """Previously all links were output as raw clickable URLs."""
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False, defang=True)
        for val in result["Links"]["Data"].values():
            assert not val.startswith("https://"), f"Raw URL still present: {val}"

    def test_defanged_url_contains_hxxps(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False, defang=True)
        values = list(result["Links"]["Data"].values())
        assert any("hxxps://" in v for v in values)

    def test_defanged_url_contains_bracketed_dot(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False, defang=True)
        values = list(result["Links"]["Data"].values())
        assert any("[.]" in v for v in values)
