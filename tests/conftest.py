import sys
import pytest
import importlib.util
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent

# Add project root to sys.path so banners/html_generator imports resolve
sys.path.insert(0, str(PROJECT_ROOT))

# Load email-analyzer.py as a module (hyphenated filename requires importlib)
spec = importlib.util.spec_from_file_location(
    "email_analyzer",
    Path(__file__).parent.parent / "email-analyzer.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

get_headers     = mod.get_headers
get_links       = mod.get_links
get_digests     = mod.get_digests
get_attachments = mod.get_attachments


def load_fixture(name: str) -> str:
    """Read a fixture .eml file and return its content as a string."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def load_fixture_bytes(name: str) -> bytes:
    """Read a fixture .eml file and return its raw bytes (mirrors the fixed main block)."""
    return (FIXTURES_DIR / name).read_bytes()


def fixture_path(name: str) -> str:
    """Return the absolute path string of a fixture file."""
    return str(FIXTURES_DIR / name)
