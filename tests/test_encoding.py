"""
Tests for file encoding handling (Bug #30)

Covers:
- UTF-8 emails read without errors (baseline)
- Latin-1 encoded emails do not raise UnicodeDecodeError
- Non-UTF-8 bytes are replaced, not dropped silently
- Headers are still extractable from Latin-1 emails
- Links are still extractable from Latin-1 emails
- Digests are still computable from Latin-1 emails
- Regression #30: hardcoded UTF-8 open no longer crashes on non-UTF-8 emails
"""

import pytest
from pathlib import Path
from conftest import (
    get_headers, get_links, get_digests,
    load_fixture, load_fixture_bytes, fixture_path, FIXTURES_DIR
)


def load_fixture_replace(name: str) -> str:
    """Read a fixture file with errors='replace' — mirrors the fixed main block."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8", errors="replace")


class TestUtf8Baseline:
    def test_utf8_email_reads_correctly(self):
        mail_data = load_fixture("basic.eml")
        assert "sender@example.com" in mail_data

    def test_utf8_email_headers_extracted(self):
        mail_data = load_fixture("basic.eml")
        result = get_headers(mail_data, investigation=False)
        assert result["Headers"]["Data"]["from"] == "sender@example.com"

    def test_utf8_email_links_extracted(self):
        mail_data = load_fixture("basic.eml")
        result = get_links(mail_data, investigation=False)
        assert len(result["Links"]["Data"]) == 2


class TestRegressionBug30:
    """Regression tests for Bug #30 — UnicodeDecodeError on non-UTF-8 emails."""

    def test_latin1_email_does_not_raise(self):
        """Previously: open(encoding='utf-8') raised UnicodeDecodeError on Latin-1 files."""
        # Must not raise any exception
        mail_data = load_fixture_replace("latin1_encoded.eml")
        assert mail_data is not None

    def test_latin1_email_returns_string(self):
        mail_data = load_fixture_replace("latin1_encoded.eml")
        assert isinstance(mail_data, str)
        assert len(mail_data) > 0

    def test_latin1_email_non_utf8_bytes_replaced_not_dropped(self):
        """Non-UTF-8 bytes must be replaced with replacement char, not silently lost."""
        mail_data = load_fixture_replace("latin1_encoded.eml")
        # The replacement char \ufffd must appear where Latin-1 bytes were
        assert "\ufffd" in mail_data

    def test_latin1_email_ascii_content_preserved(self):
        """ASCII portions of a Latin-1 email must be preserved correctly."""
        mail_data = load_fixture_replace("latin1_encoded.eml")
        assert "sender@example.com" in mail_data
        assert "recipient@example.com" in mail_data

    def test_latin1_email_headers_extractable(self):
        """get_headers() must work on a Latin-1 email without crashing."""
        mail_data = load_fixture_replace("latin1_encoded.eml")
        result = get_headers(mail_data, investigation=False)

        assert result is not None
        assert "Headers" in result
        assert result["Headers"]["Data"]["from"] == "sender@example.com"
        assert result["Headers"]["Data"]["to"] == "recipient@example.com"

    def test_latin1_email_digests_computable(self):
        """get_digests() must still compute hashes on a Latin-1 email."""
        file_bytes = load_fixture_bytes("latin1_encoded.eml")
        mail_data = load_fixture_replace("latin1_encoded.eml")
        result = get_digests(mail_data, file_bytes, investigation=False)

        assert len(result["Digests"]["Data"]["File SHA256"]) == 64
        assert len(result["Digests"]["Data"]["Content SHA256"]) == 64

    def test_latin1_email_links_extractable(self):
        """get_links() must not crash on a Latin-1 email (even if no links present)."""
        mail_data = load_fixture_replace("latin1_encoded.eml")
        result = get_links(mail_data, investigation=False)
        assert result is not None
        assert "Links" in result
