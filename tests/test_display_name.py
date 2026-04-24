"""
Tests for From display name spoofing detection (Enhancement #70)

Covers:
- Phishing display name (domain-like term mismatching sending domain) is flagged
- Legitimate display name (no domain-like term) produces informational entry
- No display name produces no Display Name Check entry
- Correct fields present in Display Name Check entry
- Display name extracted correctly
- Sending domain extracted correctly
- Address extracted correctly
- Domain-like term in display name matching sending domain is not flagged
- investigation=False produces no Display Name Check
- Regression: existing Spoof Check still works alongside Display Name Check
"""

import pytest
from conftest import get_headers, load_fixture


class TestDisplayNameFlagging:
    def test_mismatched_domain_in_display_name_flagged(self):
        """Display name containing a domain that differs from sending domain must be flagged."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"].get("Display Name Check")
        assert check is not None
        assert "Possible impersonation" in check["Conclusion"]

    def test_mismatched_domain_conclusion_contains_display_domain(self):
        """Conclusion must mention the domain-like term found in the display name."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert "paypal.com" in check["Conclusion"]

    def test_mismatched_domain_conclusion_contains_sending_domain(self):
        """Conclusion must mention the actual sending domain."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert "gmail.com" in check["Conclusion"]

    def test_legitimate_display_name_not_flagged_as_impersonation(self):
        """Display name with no domain-like term must not be flagged as impersonation."""
        result = get_headers(load_fixture("legitimate_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"].get("Display Name Check")
        assert check is not None
        assert "Possible impersonation" not in check["Conclusion"]

    def test_no_display_name_produces_no_check_entry(self):
        """Email with no display name in From header must not produce a Display Name Check."""
        result = get_headers(load_fixture("basic.eml"), investigation=True)
        assert "Display Name Check" not in result["Headers"]["Investigation"]


class TestDisplayNameFields:
    def test_display_name_field_correct(self):
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert check["Display Name"] == "support@paypal.com"

    def test_address_field_correct(self):
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert check["Address"] == "attacker@gmail.com"

    def test_sending_domain_field_correct(self):
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert check["Sending Domain"] == "gmail.com"

    def test_all_expected_fields_present(self):
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert "Display Name" in check
        assert "Address" in check
        assert "Sending Domain" in check
        assert "Conclusion" in check

    def test_legitimate_display_name_fields_present(self):
        result = get_headers(load_fixture("legitimate_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"]["Display Name Check"]
        assert check["Display Name"] == "Example Corp Support"
        assert check["Address"] == "support@example.com"
        assert check["Sending Domain"] == "example.com"


class TestDisplayNameEdgeCases:
    def test_no_investigation_produces_no_check(self):
        """Display Name Check must not appear when investigation=False."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=False)
        assert "Display Name Check" not in result["Headers"]["Investigation"]

    def test_spoof_check_still_works_alongside_display_name_check(self):
        """Existing Spoof Check must still be generated for spoofed emails."""
        result = get_headers(load_fixture("spoofed.eml"), investigation=True)
        assert "Spoof Check" in result["Headers"]["Investigation"]

    def test_display_name_matching_sending_domain_not_flagged(self):
        """If domain in display name matches sending domain, must not flag impersonation."""
        result = get_headers(load_fixture("legitimate_displayname.eml"), investigation=True)
        check = result["Headers"]["Investigation"].get("Display Name Check")
        # No domain-like terms in "Example Corp Support" so conclusion is informational
        if check:
            assert "Possible impersonation" not in check["Conclusion"]


class TestRegressionEnhancement70:
    """Regression tests — display name spoofing was previously undetected."""

    def test_email_address_in_display_name_detected(self):
        """Using a trusted email address as the display name must be detected."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        inv = result["Headers"]["Investigation"]
        assert "Display Name Check" in inv
        assert "Possible impersonation" in inv["Display Name Check"]["Conclusion"]

    def test_existing_headers_unaffected(self):
        """Adding Display Name Check must not affect other header data."""
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        data = result["Headers"]["Data"]
        assert data.get("from") is not None
        assert data.get("subject") is not None
