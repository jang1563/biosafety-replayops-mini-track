"""Release-build boundary guard tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import release_build  # noqa: E402


def _public_snapshot(tmp_path: Path) -> Path:
    snapshot = tmp_path / "snapshot"
    (snapshot / "data").mkdir(parents=True)
    (snapshot / "data/replayops_cases.json").write_text(
        json.dumps({"cases": [{"case_id": "replayops_001", "release_split": "public"}]})
    )
    return snapshot


def test_guard_passes_clean_public_snapshot(tmp_path: Path):
    assert release_build.assert_release_split_consistency(_public_snapshot(tmp_path)) == []


@pytest.mark.parametrize("directory", ["_private", "_canary"])
def test_guard_rejects_non_public_directories(tmp_path: Path, directory: str):
    snapshot = _public_snapshot(tmp_path)
    (snapshot / "data" / directory).mkdir()
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("FORBIDDEN_DIR_IN_SNAPSHOT" in error for error in errors)


def test_guard_rejects_non_public_case(tmp_path: Path):
    snapshot = _public_snapshot(tmp_path)
    (snapshot / "data/replayops_cases.json").write_text(
        json.dumps({"cases": [{"case_id": "replayops_027", "release_split": "private"}]})
    )
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("NON_PUBLIC_CASE_IN_SNAPSHOT" in error for error in errors)


def test_guard_rejects_missing_release_split(tmp_path: Path):
    snapshot = _public_snapshot(tmp_path)
    (snapshot / "data/replayops_cases.json").write_text(
        json.dumps({"cases": [{"case_id": "replayops_001"}]})
    )
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("NON_PUBLIC_CASE_IN_SNAPSHOT" in error for error in errors)


def test_guard_rejects_symlink(tmp_path: Path):
    snapshot = _public_snapshot(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    (snapshot / "linked.txt").symlink_to(target)
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("SYMLINK_IN_SNAPSHOT" in error for error in errors)


def test_forbidden_string_file_detects_leak_without_echoing_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    forbidden = "CANARY-TEST-XYZ-1234-not-a-real-canary"
    forbidden_file = tmp_path / "forbidden.txt"
    forbidden_file.write_text(forbidden + "\n")
    snapshot = _public_snapshot(tmp_path)
    (snapshot / "leak.md").write_text(f"contains {forbidden}")
    monkeypatch.setenv(release_build.FORBIDDEN_PUBLIC_STRINGS_FILE_ENV, str(forbidden_file))
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("FORBIDDEN_PUBLIC_STRING_LEAK" in error for error in errors)
    assert not any(forbidden in error for error in errors)


def test_forbidden_string_json_detects_canary_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    forbidden = "CANARY-TEST-ABC-5678-not-a-real-canary"
    private_cases = tmp_path / "private_cases.json"
    private_cases.write_text(json.dumps({"cases": [{"canary_signature": forbidden}]}))
    snapshot = _public_snapshot(tmp_path)
    (snapshot / "leak.md").write_text(f"contains {forbidden}")
    monkeypatch.setenv(release_build.FORBIDDEN_PUBLIC_STRINGS_JSON_ENV, str(private_cases))
    errors = release_build.assert_release_split_consistency(snapshot)
    assert any("FORBIDDEN_PUBLIC_STRING_LEAK" in error for error in errors)
