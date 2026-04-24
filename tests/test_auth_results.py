"""
Tests for get_auth_results() — SPF/DKIM/DMARC parsing (Enhancement #48)

Covers:
- SPF pass result extracted from Authentication-Results
- DKIM pass result extracted from Authentication-Results
- DMARC pass result extracted from Authentication-Results
- SPF fail result extracted correctly
- DKIM fail result extracted correctly
- DMARC fail result extracted correctly
- SPF softfail result extracted correctly
- Partial results (no DMARC) handled gracefully
- SPF extracted from Received-SPF when absent in Authentication-Results
- Received-SPF not used when Authentication-Results already has SPF
- No authentication headers returns empty Data
- Result is lowercase (pass/fail, not PASS/FAIL)
- Returns correct structure (Authentication > Data)
- Deterministic across multiple calls
- Regression #48: raw header values no longer needed to find auth status
"""

import pytest
from conftest import get_auth_results, load_fixture


class TestAuthResultsStructure:
    def test_returns_authentication_key(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert "Authentication" in result

    def test_returns_data_key(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert "Data" in result["Authentication"]

    def test_result_is_dict(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert isinstance(result["Authentication"]["Data"], dict)


class TestPassResults:
    def test_spf_pass_extracted(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["SPF"] == "pass"

    def test_dkim_pass_extracted(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DKIM"] == "pass"

    def test_dmarc_pass_extracted(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DMARC"] == "pass"

    def test_all_three_present_on_pass_all(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        data = result["Authentication"]["Data"]
        assert "SPF" in data
        assert "DKIM" in data
        assert "DMARC" in data


class TestFailResults:
    def test_spf_fail_extracted(self):
        mail_data = load_fixture("auth_fail_spf_dkim.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["SPF"] == "fail"

    def test_dkim_fail_extracted(self):
        mail_data = load_fixture("auth_fail_spf_dkim.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DKIM"] == "fail"

    def test_dmarc_fail_extracted(self):
        mail_data = load_fixture("auth_fail_spf_dkim.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DMARC"] == "fail"


class TestSoftfailResult:
    def test_spf_softfail_extracted(self):
        mail_data = load_fixture("auth_softfail_spf.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["SPF"] == "softfail"

    def test_dkim_pass_alongside_spf_softfail(self):
        mail_data = load_fixture("auth_softfail_spf.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DKIM"] == "pass"

    def test_no_dmarc_when_absent(self):
        """DMARC key must not appear when not present in the header."""
        mail_data = load_fixture("auth_softfail_spf.eml")
        result = get_auth_results(mail_data)
        assert "DMARC" not in result["Authentication"]["Data"]


class TestReceivedSpfFallback:
    def test_spf_extracted_from_received_spf(self):
        """When Authentication-Results is absent, SPF falls back to Received-SPF."""
        mail_data = load_fixture("auth_received_spf_only.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["SPF"] == "pass"

    def test_received_spf_fallback_no_dkim_or_dmarc(self):
        """Received-SPF fallback must not invent DKIM or DMARC results."""
        mail_data = load_fixture("auth_received_spf_only.eml")
        result = get_auth_results(mail_data)
        data = result["Authentication"]["Data"]
        assert "DKIM" not in data
        assert "DMARC" not in data

    def test_auth_results_spf_takes_priority_over_received_spf(self):
        """If Authentication-Results has SPF, Received-SPF must not override it."""
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        # auth_pass_all.eml has spf=pass in Authentication-Results — must stay pass
        assert result["Authentication"]["Data"]["SPF"] == "pass"


class TestNoAuthHeaders:
    def test_no_auth_headers_returns_empty_data(self):
        mail_data = load_fixture("auth_no_headers.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"] == {}

    def test_no_auth_headers_no_crash(self):
        mail_data = load_fixture("auth_no_headers.eml")
        result = get_auth_results(mail_data)
        assert result is not None

    def test_basic_email_no_crash(self):
        mail_data = load_fixture("basic.eml")
        result = get_auth_results(mail_data)
        assert result is not None


class TestResultFormat:
    def test_results_are_lowercase(self):
        """Result values must be lowercase (pass, not PASS)."""
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        for key, value in result["Authentication"]["Data"].items():
            assert value == value.lower(), f"{key} value '{value}' is not lowercase"

    def test_results_are_deterministic(self):
        mail_data = load_fixture("auth_pass_all.eml")
        result1 = get_auth_results(mail_data)
        result2 = get_auth_results(mail_data)
        assert result1["Authentication"]["Data"] == result2["Authentication"]["Data"]


class TestRegressionEnhancement48:
    """Regression tests for Enhancement #48 — auth status buried in raw header strings."""

    def test_spf_status_accessible_as_structured_field(self):
        """Previously SPF result was only in the raw 'authentication-results' string."""
        mail_data = load_fixture("auth_fail_spf_dkim.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["SPF"] == "fail"

    def test_dmarc_status_accessible_as_structured_field(self):
        mail_data = load_fixture("auth_fail_spf_dkim.eml")
        result = get_auth_results(mail_data)
        assert result["Authentication"]["Data"]["DMARC"] == "fail"

    def test_auth_data_does_not_require_raw_header_parsing(self):
        """Caller must not need to parse raw header text to get SPF/DKIM/DMARC status."""
        mail_data = load_fixture("auth_pass_all.eml")
        result = get_auth_results(mail_data)
        data = result["Authentication"]["Data"]

        # Direct key access must work without any string manipulation
        assert data.get("SPF") in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")
        assert data.get("DKIM") in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")
        assert data.get("DMARC") in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")
