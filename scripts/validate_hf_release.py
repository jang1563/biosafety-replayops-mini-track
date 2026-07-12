#!/usr/bin/env python3
"""Validate an allowlisted Hugging Face dataset staging directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from huggingface_hub import DatasetCard

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "release" / "public_release_manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def validate(staging: Path) -> list[str]:
    staging = staging.resolve()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected = set(manifest["huggingface_allowed_paths"])
    actual = {
        path.relative_to(staging).as_posix()
        for path in staging.rglob("*")
        if path.is_file()
    }
    errors: list[str] = []

    if actual != expected:
        errors.append(f"HF_FILE_SET_MISMATCH missing={sorted(expected - actual)} extra={sorted(actual - expected)}")

    sums_path = staging / "SHA256SUMS.txt"
    if sums_path.exists():
        expected_sums: dict[str, str] = {}
        for line in sums_path.read_text().splitlines():
            digest, separator, relpath = line.partition("  ")
            if not separator or not relpath or Path(relpath).is_absolute():
                errors.append(f"INVALID_CHECKSUM_LINE: {line}")
                continue
            expected_sums[relpath] = digest
        checksum_targets = expected - {"SHA256SUMS.txt"}
        if set(expected_sums) != checksum_targets:
            errors.append("CHECKSUM_FILE_SET_MISMATCH")
        for relpath, digest in expected_sums.items():
            target = staging / relpath
            if target.exists() and _sha256(target) != digest:
                errors.append(f"CHECKSUM_MISMATCH: {relpath}")

    cases_payload = json.loads((staging / "data/replayops_cases.json").read_text())
    fixtures_payload = json.loads((staging / "data/fixture_traces.json").read_text())
    cases = cases_payload.get("cases", [])
    fixtures = fixtures_payload.get("fixtures", [])
    if len(cases) != 26 or len(fixtures) != 52:
        errors.append(f"HF_COUNT_MISMATCH cases={len(cases)} fixtures={len(fixtures)}")
    if any(case.get("release_split") != "public" or case.get("canary_signature") for case in cases):
        errors.append("HF_NON_PUBLIC_CASE_OR_ACTIVE_CANARY")
    if _jsonl_rows(staging / "data/replayops_cases.jsonl") != cases:
        errors.append("HF_CASE_JSONL_NOT_EQUIVALENT")
    if _jsonl_rows(staging / "data/fixture_traces.jsonl") != fixtures:
        errors.append("HF_FIXTURE_JSONL_NOT_EQUIVALENT")

    card_path = staging / "README.md"
    card_text = card_path.read_text(encoding="utf-8")
    try:
        card = DatasetCard.load(str(card_path))
        metadata = card.data.to_dict()
    except Exception as exc:
        errors.append(f"HF_CARD_METADATA_INVALID: {type(exc).__name__}: {exc}")
        metadata = {}

    expected_configs = [
        {
            "config_name": "cases",
            "data_files": [{"split": "public", "path": "data/replayops_cases.jsonl"}],
        },
        {
            "config_name": "fixtures",
            "data_files": [{"split": "public", "path": "data/fixture_traces.jsonl"}],
        },
    ]
    if metadata.get("license") != "apache-2.0":
        errors.append("HF_CARD_LICENSE_MISMATCH")
    if metadata.get("configs") != expected_configs:
        errors.append("HF_CARD_CONFIGS_MISMATCH")
    if metadata.get("task_categories") != ["text-classification"]:
        errors.append("HF_CARD_TASK_CATEGORY_MISMATCH")
    if "not a live model benchmark" not in card_text:
        errors.append("HF_CARD_NONCLAIM_MISSING")

    for path in sorted(actual):
        full_path = staging / path
        if full_path.is_symlink():
            errors.append(f"HF_SYMLINK_NOT_ALLOWED: {path}")
            continue
        if full_path.stat().st_size > manifest["max_text_scan_bytes"]:
            errors.append(f"HF_FILE_TOO_LARGE: {path}")
            continue
        text = full_path.read_text(encoding="utf-8", errors="ignore").casefold()
        for literal in manifest["forbidden_literals"]:
            if literal.casefold() in text:
                errors.append(f"HF_FORBIDDEN_LITERAL: {path}: {literal}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("staging", type=Path)
    args = parser.parse_args()
    errors = validate(args.staging)
    if errors:
        print("HF_RELEASE_VALIDATION_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("HF_RELEASE_VALIDATION_OK files=12 cases=26 fixtures=52")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
