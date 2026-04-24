"""
Tests for CLI argument validation and error handling.

Covers:
- Missing file exits with error code and friendly message (#61)
- Unsupported input file format exits with error
- Unsupported output format exits with error before analysis
- Valid file runs without error
- --version flag prints version and exits with code 0 (#75)
"""

import subprocess
import sys
import os
import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "email-analyzer.py")


def run_cli(*args):
    """Run the CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


class TestRegressionBug61:
    """Regression tests for Bug #61 — missing file causes unhandled FileNotFoundError."""

    def test_missing_file_exits_nonzero(self):
        """Non-existent file must cause a clean exit with a non-zero code."""
        returncode, _, _ = run_cli("-f", "does_not_exist.eml")
        assert returncode != 0

    def test_missing_file_prints_friendly_message(self):
        """Non-existent file must print a user-friendly message, not a traceback."""
        _, stdout, stderr = run_cli("-f", "does_not_exist.eml")
        combined = stdout + stderr
        assert "File not found" in combined

    def test_missing_file_no_traceback(self):
        """Non-existent file must not produce a Python traceback."""
        _, stdout, stderr = run_cli("-f", "does_not_exist.eml")
        combined = stdout + stderr
        assert "Traceback" not in combined
        assert "FileNotFoundError" not in combined

    def test_unsupported_extension_exits_nonzero(self):
        """Unsupported file extension must exit with non-zero code."""
        returncode, _, _ = run_cli("-f", "sample.txt")
        assert returncode != 0

    def test_unsupported_output_format_exits_before_analysis(self):
        """Unsupported output format must exit before any analysis runs."""
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "basic.eml")
        returncode, stdout, _ = run_cli("-f", fixture, "-o", "report.xyz")
        assert returncode != 0
        # No analysis banner should appear — exited before any work
        assert "EmailAnalyzer" not in stdout


class TestVersionFlag:
    """Tests for the --version flag (Enhancement #75)."""

    def test_version_exits_zero(self):
        returncode, _, _ = run_cli("--version")
        assert returncode == 0

    def test_version_prints_version_number(self):
        _, stdout, stderr = run_cli("--version")
        combined = stdout + stderr
        assert "2.0" in combined

    def test_version_works_without_filename(self):
        """--version must not require -f to be present."""
        returncode, _, _ = run_cli("--version")
        assert returncode == 0

    def test_version_output_contains_script_name(self):
        _, stdout, stderr = run_cli("--version")
        combined = stdout + stderr
        assert "email-analyzer" in combined
