"""
Tests for Reply-To domain investigation (Enhancement #73)

Covers:
- Reply-To domain differs from From domain → entry added with mismatch conclusion
- Reply-To domain matches From domain → entry added with match conclusion
- No Reply-To header → no Reply-To Domain Check entry
- investigation=False → no Reply-To Domain Check entry
- Entry fields: Reply-To Address, Reply-To Domain, From Address, From Domain, Conclusion
- Existing Spoof Check unaffected
"""

import pytest
from conftest import get_headers, load_fixture


class TestReplyToDomainMismatch:
    def test_mismatch_entry_added(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        assert "Reply-To Domain Check" in result["Headers"]["Investigation"]

    def test_mismatch_conclusion_mentions_differs(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert "differ" in entry["Conclusion"].lower()

    def test_mismatch_replyto_domain_value(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert entry["Reply-To Domain"] == "evil.com"

    def test_mismatch_from_domain_value(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert entry["From Domain"] == "bank.com"

    def test_mismatch_replyto_address_value(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert entry["Reply-To Address"] == "attacker@evil.com"

    def test_mismatch_from_address_value(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert entry["From Address"] == "support@bank.com"


class TestReplyToDomainMatch:
    def test_same_domain_entry_added(self):
        result = get_headers(load_fixture("replyto_same_domain.eml"), investigation=True)
        assert "Reply-To Domain Check" in result["Headers"]["Investigation"]

    def test_same_domain_conclusion_mentions_matches(self):
        result = get_headers(load_fixture("replyto_same_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert "match" in entry["Conclusion"].lower()


class TestReplyToDomainAbsent:
    def test_no_replyto_no_entry(self):
        result = get_headers(load_fixture("clean_headers.eml"), investigation=True)
        assert "Reply-To Domain Check" not in result["Headers"]["Investigation"]

    def test_investigation_false_no_entry(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=False)
        assert "Reply-To Domain Check" not in result["Headers"]["Investigation"]


class TestRegressionEnhancement73:
    def test_spoof_check_still_present(self):
        result = get_headers(load_fixture("spoofed.eml"), investigation=True)
        assert "Spoof Check" in result["Headers"]["Investigation"]

    def test_display_name_check_unaffected(self):
        result = get_headers(load_fixture("phishing_displayname.eml"), investigation=True)
        assert "Display Name Check" in result["Headers"]["Investigation"]

    def test_entry_is_dict(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert isinstance(entry, dict)

    def test_entry_has_expected_keys(self):
        result = get_headers(load_fixture("replyto_diff_domain.eml"), investigation=True)
        entry = result["Headers"]["Investigation"]["Reply-To Domain Check"]
        assert set(entry.keys()) == {"Reply-To Address", "Reply-To Domain", "From Address", "From Domain", "Conclusion"}
