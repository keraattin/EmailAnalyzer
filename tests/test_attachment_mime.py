"""
Tests for attachment MIME type in output (Enhancement #49)

Covers:
- Data values are dicts with 'filename' and 'mime_type' keys
- application/octet-stream MIME type captured for binary attachment
- image/png MIME type captured for image attachment
- MIME type is a non-empty string
- MIME type follows type/subtype format
- Multiple attachments each have their own mime_type
- Filename still correct alongside mime_type
- No attachments returns empty Data
- mime_type present regardless of investigation flag
- Regression #49: MIME type was previously absent from output
"""

import pytest
from conftest import get_attachments, fixture_path


class TestDataStructure:
    def test_data_value_is_dict(self):
        """Data entry must be a dict, not a plain string."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]
        assert isinstance(data["1"], dict)

    def test_data_value_has_filename_key(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert "filename" in result["Attachments"]["Data"]["1"]

    def test_data_value_has_mime_type_key(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert "mime_type" in result["Attachments"]["Data"]["1"]

    def test_filename_value_correct(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"]["1"]["filename"] == "malware.pdf"

    def test_no_attachments_still_empty(self):
        result = get_attachments(fixture_path("no_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"] == {}


class TestMimeTypeValues:
    def test_binary_attachment_mime_type(self):
        """application/octet-stream must be captured for binary attachment."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"]["1"]["mime_type"] == "application/octet-stream"

    def test_image_attachment_mime_type(self):
        """image/png must be captured for PNG image attachment."""
        result = get_attachments(fixture_path("image_attachment.eml"), investigation=False)
        assert result["Attachments"]["Data"]["1"]["mime_type"] == "image/png"

    def test_mime_type_is_non_empty_string(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        mime = result["Attachments"]["Data"]["1"]["mime_type"]
        assert isinstance(mime, str)
        assert len(mime) > 0

    def test_mime_type_contains_slash(self):
        """MIME type must follow the type/subtype format."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        mime = result["Attachments"]["Data"]["1"]["mime_type"]
        assert "/" in mime

    def test_multiple_attachments_each_have_mime_type(self):
        result = get_attachments(fixture_path("multi_attachment.eml"), investigation=False)
        data = result["Attachments"]["Data"]
        for idx, val in data.items():
            assert "mime_type" in val, f"Attachment {idx} missing mime_type"
            assert len(val["mime_type"]) > 0

    def test_mime_type_present_with_investigation_disabled(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        assert "mime_type" in result["Attachments"]["Data"]["1"]

    def test_mime_type_present_with_investigation_enabled(self):
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=True)
        assert "mime_type" in result["Attachments"]["Data"]["1"]

    def test_image_filename_and_mime_type_together(self):
        """filename and mime_type must both be correct for image attachment."""
        result = get_attachments(fixture_path("image_attachment.eml"), investigation=False)
        entry = result["Attachments"]["Data"]["1"]
        assert entry["filename"] == "logo.png"
        assert entry["mime_type"] == "image/png"


class TestRegressionEnhancement49:
    """Regression tests for Enhancement #49 — MIME type absent from attachment output."""

    def test_mime_type_was_previously_absent(self):
        """Previously Data['1'] was a plain string (filename only). Now it must be a dict."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        entry = result["Attachments"]["Data"]["1"]
        assert not isinstance(entry, str), "Data value must be a dict, not a plain string"

    def test_mime_type_accessible_without_string_parsing(self):
        """Caller must not need to parse raw headers to get the MIME type."""
        result = get_attachments(fixture_path("image_attachment.eml"), investigation=False)
        mime = result["Attachments"]["Data"]["1"]["mime_type"]
        assert mime == "image/png"

    def test_disguised_file_mime_type_detectable(self):
        """A file with a .pdf extension but binary MIME type must expose the true type."""
        result = get_attachments(fixture_path("binary_attachment.eml"), investigation=False)
        entry = result["Attachments"]["Data"]["1"]
        # malware.pdf has application/octet-stream, not application/pdf
        assert entry["filename"] == "malware.pdf"
        assert entry["mime_type"] == "application/octet-stream"
        assert entry["mime_type"] != "application/pdf"
