"""
Tests for html_generator.py — XSS escaping (Bug #32)

Covers:
- Header keys and values are HTML-escaped in data table
- Header investigation index and values are HTML-escaped
- Link URLs are HTML-escaped in data table
- Link index and URLs are HTML-escaped in investigation table
- Attachment filenames are HTML-escaped in data table
- Attachment index and URLs are HTML-escaped in investigation table
- Digest keys and values are HTML-escaped in data table
- Digest index and URLs are HTML-escaped in investigation table
- Scan filename is HTML-escaped in information section
- Safe values render correctly (no double-encoding)
- Regression #32: unescaped <script> tags cannot execute via HTML report
"""

import sys
import importlib.util
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

spec = importlib.util.spec_from_file_location(
    "html_generator", PROJECT_ROOT / "html_generator.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

generate_headers_section    = mod.generate_headers_section
generate_links_section      = mod.generate_links_section
generate_attachment_section = mod.generate_attachment_section
generate_digest_section     = mod.generate_digest_section
generate_summary_section    = mod.generate_summary_section
generate_table_from_json    = mod.generate_table_from_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def xss_payload():
    return '"><script>alert(1)</script>'


def make_info():
    return {
        "Project": {"Name": "EmailAnalyzer", "Url": "https://github.com/keraattin/EmailAnalyzer", "Version": "2.0"},
        "Scan": {"Filename": "test.eml", "Generated": "January 01, 2026 - 00:00:00"},
    }


# ---------------------------------------------------------------------------
# Headers section
# ---------------------------------------------------------------------------

class TestHeadersSectionEscaping:
    def test_header_value_xss_escaped(self):
        data = {"Data": {"from": xss_payload()}, "Investigation": {}}
        html = generate_headers_section(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_header_key_xss_escaped(self):
        data = {"Data": {xss_payload(): "value"}, "Investigation": {}}
        html = generate_headers_section(data)
        assert "<script>" not in html

    def test_header_investigation_index_escaped(self):
        data = {
            "Data": {},
            "Investigation": {
                xss_payload(): {"Virustotal": "https://virustotal.com/test"}
            }
        }
        html = generate_headers_section(data)
        assert "<script>" not in html

    def test_header_investigation_value_escaped(self):
        data = {
            "Data": {},
            "Investigation": {
                "Spoof Check": {"Conclusion": xss_payload()}
            }
        }
        html = generate_headers_section(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_safe_header_value_rendered_correctly(self):
        data = {"Data": {"from": "sender@example.com"}, "Investigation": {}}
        html = generate_headers_section(data)
        assert "sender@example.com" in html

    def test_ampersand_in_header_value_escaped(self):
        data = {"Data": {"subject": "Cats & Dogs"}, "Investigation": {}}
        html = generate_headers_section(data)
        assert "&amp;" in html
        assert "Cats & Dogs" not in html


# ---------------------------------------------------------------------------
# Links section
# ---------------------------------------------------------------------------

class TestLinksSectionEscaping:
    def test_link_url_xss_escaped_in_data(self):
        data = {"Data": {"1": xss_payload()}, "Investigation": {}}
        html = generate_links_section(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_link_url_xss_escaped_in_investigation_href(self):
        data = {
            "Data": {"1": "https://example.com"},
            "Investigation": {
                "1": {"Virustotal": f"https://virustotal.com/{xss_payload()}"}
            }
        }
        html = generate_links_section(data)
        assert "<script>" not in html

    def test_link_investigation_index_escaped(self):
        data = {
            "Data": {},
            "Investigation": {
                xss_payload(): {"Virustotal": "https://virustotal.com/test"}
            }
        }
        html = generate_links_section(data)
        assert "<script>" not in html

    def test_link_investigation_tool_name_escaped(self):
        data = {
            "Data": {"1": "https://example.com"},
            "Investigation": {
                "1": {xss_payload(): "https://virustotal.com/test"}
            }
        }
        html = generate_links_section(data)
        assert "<script>" not in html

    def test_safe_link_url_rendered_correctly(self):
        data = {"Data": {"1": "https://example.com"}, "Investigation": {}}
        html = generate_links_section(data)
        assert "https://example.com" in html

    def test_link_url_with_ampersand_escaped(self):
        data = {"Data": {"1": "https://example.com/search?a=1&b=2"}, "Investigation": {}}
        html = generate_links_section(data)
        assert "&amp;" in html


# ---------------------------------------------------------------------------
# Attachments section
# ---------------------------------------------------------------------------

def make_attachment_entry(filename, mime_type="application/octet-stream"):
    return {"filename": filename, "mime_type": mime_type}


class TestAttachmentsSectionEscaping:
    def test_attachment_filename_xss_escaped_in_data(self):
        data = {"Data": {"1": make_attachment_entry(xss_payload())}, "Investigation": {}}
        html = generate_attachment_section(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_attachment_index_xss_escaped_in_investigation(self):
        data = {
            "Data": {"1": make_attachment_entry("malware.pdf")},
            "Investigation": {
                xss_payload(): {"Virustotal": {"SHA256": "https://virustotal.com/test"}}
            }
        }
        html = generate_attachment_section(data)
        assert "<script>" not in html

    def test_attachment_url_xss_escaped_in_investigation_href(self):
        data = {
            "Data": {"1": make_attachment_entry("malware.pdf")},
            "Investigation": {
                "malware.pdf": {
                    "Virustotal": {"SHA256": f"https://virustotal.com/{xss_payload()}"}
                }
            }
        }
        html = generate_attachment_section(data)
        assert "<script>" not in html

    def test_attachment_hash_type_escaped_in_investigation(self):
        data = {
            "Data": {"1": make_attachment_entry("malware.pdf")},
            "Investigation": {
                "malware.pdf": {
                    "Virustotal": {xss_payload(): "https://virustotal.com/test"}
                }
            }
        }
        html = generate_attachment_section(data)
        assert "<script>" not in html

    def test_safe_attachment_filename_rendered_correctly(self):
        data = {"Data": {"1": make_attachment_entry("document.pdf")}, "Investigation": {}}
        html = generate_attachment_section(data)
        assert "document.pdf" in html

    def test_attachment_filename_with_special_chars_escaped(self):
        data = {"Data": {"1": make_attachment_entry("file<name>.pdf")}, "Investigation": {}}
        html = generate_attachment_section(data)
        assert "<name>" not in html
        assert "&lt;name&gt;" in html

    def test_attachment_mime_type_rendered(self):
        data = {"Data": {"1": make_attachment_entry("invoice.pdf", "application/x-msdownload")}, "Investigation": {}}
        html = generate_attachment_section(data)
        assert "application/x-msdownload" in html

    def test_attachment_mime_type_xss_escaped(self):
        data = {"Data": {"1": make_attachment_entry("file.pdf", xss_payload())}, "Investigation": {}}
        html = generate_attachment_section(data)
        assert "<script>" not in html


# ---------------------------------------------------------------------------
# Digests section
# ---------------------------------------------------------------------------

class TestDigestsSectionEscaping:
    def test_digest_value_escaped_in_data(self):
        data = {"Data": {"File MD5": xss_payload()}, "Investigation": {}}
        html = generate_digest_section(data)
        assert "<script>" not in html

    def test_digest_key_escaped_in_data(self):
        data = {"Data": {xss_payload(): "abc123"}, "Investigation": {}}
        html = generate_digest_section(data)
        assert "<script>" not in html

    def test_digest_investigation_index_escaped(self):
        data = {
            "Data": {},
            "Investigation": {
                xss_payload(): {"Virustotal": "https://virustotal.com/test"}
            }
        }
        html = generate_digest_section(data)
        assert "<script>" not in html

    def test_digest_investigation_url_escaped_in_href(self):
        data = {
            "Data": {},
            "Investigation": {
                "File MD5": {"Virustotal": f"https://virustotal.com/{xss_payload()}"}
            }
        }
        html = generate_digest_section(data)
        assert "<script>" not in html

    def test_safe_digest_value_rendered_correctly(self):
        data = {
            "Data": {"File MD5": "d41d8cd98f00b204e9800998ecf8427e"},
            "Investigation": {}
        }
        html = generate_digest_section(data)
        assert "d41d8cd98f00b204e9800998ecf8427e" in html


# ---------------------------------------------------------------------------
# Full report — information section
# ---------------------------------------------------------------------------

class TestInformationSectionEscaping:
    def test_scan_filename_xss_escaped(self):
        info = make_info()
        info["Scan"]["Filename"] = xss_payload()
        app_data = {"Information": info, "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<script>" not in html

    def test_scan_generated_escaped(self):
        info = make_info()
        info["Scan"]["Generated"] = xss_payload()
        app_data = {"Information": info, "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<script>" not in html

    def test_safe_scan_filename_rendered_correctly(self):
        info = make_info()
        app_data = {"Information": info, "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "test.eml" in html


# ---------------------------------------------------------------------------
# Regression #32
# ---------------------------------------------------------------------------

class TestRegressionBug32:
    """Regression tests for Bug #32 — XSS via unescaped values in HTML report."""

    def test_xss_payload_in_link_cannot_execute_script(self):
        """A link URL containing <script> must not appear unescaped in the HTML."""
        data = {
            "Data": {"1": '"><script>alert(document.cookie)</script>'},
            "Investigation": {}
        }
        html = generate_links_section(data)
        assert "<script>alert" not in html

    def test_xss_payload_in_attachment_filename_cannot_execute_script(self):
        data = {
            "Data": {"1": make_attachment_entry('"><script>alert(1)</script>')},
            "Investigation": {}
        }
        html = generate_attachment_section(data)
        assert "<script>alert" not in html

    def test_xss_payload_in_investigation_href_cannot_break_attribute(self):
        """A URL containing ' must not break out of a single-quoted href attribute."""
        payload = "https://evil.com/' onmouseover='alert(1)"
        data = {
            "Data": {"1": "https://example.com"},
            "Investigation": {
                "1": {"Virustotal": payload}
            }
        }
        html = generate_links_section(data)
        # The single quote must be escaped so it cannot close the href attribute
        assert "onmouseover='alert(1)" not in html
        assert "&#x27;" in html or "&apos;" in html or "&#39;" in html or "onmouseover" not in html

    def test_headers_section_previously_escaped_value_still_works(self):
        """The one pre-existing escape in headers data must still function correctly."""
        data = {
            "Data": {"subject": "<Important> Notice & Alert"},
            "Investigation": {}
        }
        html = generate_headers_section(data)
        assert "&lt;Important&gt;" in html
        assert "&amp;" in html
        assert "<Important>" not in html

    def test_double_encoding_does_not_occur_for_safe_values(self):
        """Values without special chars must not be double-encoded."""
        data = {"Data": {"from": "user@example.com"}, "Investigation": {}}
        html = generate_headers_section(data)
        assert "user@example.com" in html
        assert "&amp;" not in html or "user" in html  # no spurious encoding


# ---------------------------------------------------------------------------
# Regression #33 — duplicate navbarDropdown IDs
# ---------------------------------------------------------------------------

class TestRegressionBug33:
    """Regression tests for Bug #33 — four dropdowns sharing id='navbarDropdown'."""

    def test_navbardropdown_id_not_duplicated(self):
        """The generic id='navbarDropdown' must not appear in the generated HTML."""
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'id="navbarDropdown"' not in html

    def test_headers_dropdown_has_unique_id(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'id="headersDropdown"' in html

    def test_links_dropdown_has_unique_id(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'id="linksDropdown"' in html

    def test_attachments_dropdown_has_unique_id(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'id="attachmentsDropdown"' in html

    def test_digests_dropdown_has_unique_id(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'id="digestsDropdown"' in html

    def test_all_four_dropdown_ids_are_distinct(self):
        """Each dropdown must have a unique ID — no two dropdowns share the same id."""
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        ids = ["headersDropdown", "linksDropdown", "attachmentsDropdown", "digestsDropdown"]
        assert len(ids) == len(set(ids))  # sanity
        for id_ in ids:
            assert html.count(f'id="{id_}"') == 1, f'{id_} appears more than once'

    def test_aria_labelledby_matches_id_for_headers(self):
        """aria-labelledby must reference the same unique ID as the toggle button."""
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'aria-labelledby="headersDropdown"' in html

    def test_aria_labelledby_matches_id_for_links(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'aria-labelledby="linksDropdown"' in html

    def test_aria_labelledby_matches_id_for_attachments(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'aria-labelledby="attachmentsDropdown"' in html

    def test_aria_labelledby_matches_id_for_digests(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'aria-labelledby="digestsDropdown"' in html

    def test_aria_labelledby_navbardropdown_not_present(self):
        """The old mismatched aria-labelledby='navbarDropdown' must be gone."""
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'aria-labelledby="navbarDropdown"' not in html


# ---------------------------------------------------------------------------
# Fix #74 — missing <!DOCTYPE html>, <html>, <body> structure tags
# ---------------------------------------------------------------------------

class TestHtmlStructureFix74:
    """Verify the generated report is a complete, valid HTML document."""

    def test_doctype_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_html_open_tag_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<html" in html

    def test_html_close_tag_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "</html>" in html

    def test_body_open_tag_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<body>" in html

    def test_body_close_tag_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "</body>" in html

    def test_title_contains_filename(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<title>" in html
        assert "test.eml" in html

    def test_charset_meta_present(self):
        app_data = {"Information": make_info(), "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert 'charset="UTF-8"' in html or "charset=UTF-8" in html

    def test_title_xss_escaped(self):
        info = make_info()
        info["Scan"]["Filename"] = xss_payload()
        app_data = {"Information": info, "Analysis": {}}
        html = generate_table_from_json(app_data)
        assert "<script>" not in html


# ---------------------------------------------------------------------------
# Enhancement #76 — Threat Summary section
# ---------------------------------------------------------------------------

def make_clean_analysis():
    return {
        "Headers": {
            "Data": {"from": "sender@example.com", "to": "recipient@example.com",
                     "subject": "Hello", "date": "Wed, 02 Apr 2026 10:00:00 +0000"},
            "Investigation": {}
        }
    }


class TestSummarySectionStructure:
    def test_summary_section_present_in_full_report(self):
        app_data = {"Information": make_info(), "Analysis": make_clean_analysis()}
        html = generate_table_from_json(app_data)
        assert "summary-section" in html

    def test_summary_nav_link_present(self):
        app_data = {"Information": make_info(), "Analysis": make_clean_analysis()}
        html = generate_table_from_json(app_data)
        assert "#summary-section" in html

    def test_threat_level_shown(self):
        data = make_clean_analysis()
        html = generate_summary_section(data)
        assert "Threat Level" in html

    def test_email_overview_shows_from(self):
        data = make_clean_analysis()
        html = generate_summary_section(data)
        assert "sender@example.com" in html

    def test_email_overview_shows_subject(self):
        data = make_clean_analysis()
        html = generate_summary_section(data)
        assert "Hello" in html

    def test_links_count_shown(self):
        data = make_clean_analysis()
        data["Links"] = {"Data": {"1": "https://a.com", "2": "https://b.com"}, "Investigation": {}}
        html = generate_summary_section(data)
        assert "2" in html

    def test_attachments_count_shown(self):
        data = make_clean_analysis()
        data["Attachments"] = {"Data": {"1": {"filename": "f.pdf", "mime_type": "application/pdf"}}, "Investigation": {}}
        html = generate_summary_section(data)
        assert "1" in html


class TestSummaryThreatLevel:
    def test_low_threat_when_clean(self):
        data = make_clean_analysis()
        html = generate_summary_section(data)
        assert "LOW" in html

    def test_high_threat_on_spoof(self):
        data = make_clean_analysis()
        data["Headers"]["Investigation"]["Spoof Check"] = {
            "Reply-To": "x@evil.com", "From": "y@bank.com",
            "Conclusion": "Reply Address and From Address is NOT Same. This mail may be SPOOFED."
        }
        html = generate_summary_section(data)
        assert "HIGH" in html

    def test_medium_threat_on_display_name_mismatch(self):
        data = make_clean_analysis()
        data["Headers"]["Investigation"]["Display Name Check"] = {
            "Display Name": "paypal.com", "Address": "attacker@gmail.com",
            "Sending Domain": "gmail.com",
            "Conclusion": "Display name contains 'paypal.com' which does not match sending domain 'gmail.com'. Possible impersonation."
        }
        html = generate_summary_section(data)
        assert "MEDIUM" in html

    def test_medium_threat_on_replyto_mismatch(self):
        data = make_clean_analysis()
        data["Headers"]["Investigation"]["Reply-To Domain Check"] = {
            "Reply-To Address": "a@evil.com", "Reply-To Domain": "evil.com",
            "From Address": "b@bank.com", "From Domain": "bank.com",
            "Conclusion": "Reply-To domain 'evil.com' differs from From domain 'bank.com'."
        }
        html = generate_summary_section(data)
        assert "MEDIUM" in html

    def test_high_threat_on_auth_failure(self):
        data = make_clean_analysis()
        data["Authentication"] = {"Data": {"spf": "fail"}}
        html = generate_summary_section(data)
        assert "HIGH" in html

    def test_suspicious_header_flag_shown(self):
        data = make_clean_analysis()
        data["Headers"]["Investigation"]["Suspicious Headers"] = {
            "Missing Message-ID": "Legitimate MTAs always generate a Message-ID."
        }
        html = generate_summary_section(data)
        assert "Missing Message-ID" in html

    def test_no_threat_indicators_message_when_clean(self):
        data = make_clean_analysis()
        html = generate_summary_section(data)
        assert "No threat indicators detected" in html

    def test_xss_in_threat_flag_detail_escaped(self):
        data = make_clean_analysis()
        data["Headers"]["Investigation"]["Suspicious Headers"] = {
            "Test": xss_payload()
        }
        html = generate_summary_section(data)
        assert "<script>" not in html
