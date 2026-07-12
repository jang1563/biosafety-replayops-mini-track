"""End-to-end tests for deterministic Hugging Face staging."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_hf_release  # noqa: E402
import check_public_manifest  # noqa: E402
import validate_hf_release  # noqa: E402


def test_hf_release_round_trip(tmp_path: Path):
    staging = tmp_path / "hf"
    build_hf_release.build(staging)
    assert validate_hf_release.validate(staging) == []
    assert not list(staging.rglob("*.tar.gz"))
    assert all(not line.split("  ", 1)[1].startswith("/") for line in (staging / "SHA256SUMS.txt").read_text().splitlines())


def test_hf_validator_rejects_extra_file(tmp_path: Path):
    staging = tmp_path / "hf"
    build_hf_release.build(staging)
    (staging / "unexpected.txt").write_text("unexpected")
    errors = validate_hf_release.validate(staging)
    assert any("HF_FILE_SET_MISMATCH" in error for error in errors)


def test_hf_validator_rejects_invalid_card_yaml(tmp_path: Path):
    staging = tmp_path / "hf"
    build_hf_release.build(staging)
    (staging / "README.md").write_text("---\nlicense: [\n---\n# Broken card\n")
    errors = validate_hf_release.validate(staging)
    assert any("HF_CARD_METADATA_INVALID" in error for error in errors)


def test_public_scan_allows_github_service_email_but_rejects_personal_email():
    assert check_public_manifest.scan_text(
        "noreply@github.com support@github.com",
        "commit",
        [],
    ) == []
    personal_email = "person" + "@" + "example.com"
    errors = check_public_manifest.scan_text(personal_email, "blob", [])
    assert any("DIRECT_EMAIL" in error for error in errors)
