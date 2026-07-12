#!/usr/bin/env python3
"""Validate the current research-only public tree and dataset identity."""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "release" / "public_release_manifest.json"
MANIFEST_RELPATH = "release/public_release_manifest.json"

CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ALLOWED_SERVICE_EMAILS = {"noreply@github.com", "support@github.com"}


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def repository_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(path for path in result.stdout.splitlines() if path)


def path_is_forbidden(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def scan_text(
    text: str,
    path: str,
    forbidden_literals: list[str],
    *,
    skip_policy_literals: bool = False,
) -> list[str]:
    errors: list[str] = []
    lowered = text.casefold()

    if not skip_policy_literals:
        for literal in forbidden_literals:
            if literal.casefold() in lowered:
                errors.append(f"FORBIDDEN_LITERAL: {path}: {literal}")

    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(text):
            errors.append(f"CREDENTIAL_SHAPED_STRING: {path}: {pattern.pattern}")

    for email in EMAIL_PATTERN.findall(text):
        if email not in ALLOWED_SERVICE_EMAILS and not email.endswith("@users.noreply.github.com"):
            errors.append(f"DIRECT_EMAIL: {path}: {email}")

    return errors


def _jsonl_rows(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _validate_dataset(manifest: dict) -> list[str]:
    errors: list[str] = []
    expected = manifest["expected_counts"]
    schema_version = manifest["dataset_schema_version"]

    cases_payload = json.loads((ROOT / "data/replayops_cases.json").read_text())
    fixtures_payload = json.loads((ROOT / "data/fixture_traces.json").read_text())
    case_rows = cases_payload.get("cases", [])
    fixture_rows = fixtures_payload.get("fixtures", [])

    if cases_payload.get("schema_version") != schema_version:
        errors.append("CASE_SCHEMA_VERSION_MISMATCH")
    if fixtures_payload.get("schema_version") != schema_version:
        errors.append("FIXTURE_SCHEMA_VERSION_MISMATCH")
    if len(case_rows) != expected["cases"]:
        errors.append(f"CASE_COUNT_MISMATCH: {len(case_rows)}")
    if len(fixture_rows) != expected["fixtures"]:
        errors.append(f"FIXTURE_COUNT_MISMATCH: {len(fixture_rows)}")

    non_public = [row.get("case_id") for row in case_rows if row.get("release_split") != "public"]
    if non_public:
        errors.append(f"NON_PUBLIC_CASES: {non_public}")
    active_canaries = [row.get("case_id") for row in case_rows if row.get("canary_signature")]
    if active_canaries:
        errors.append(f"ACTIVE_CASE_CANARIES: {active_canaries}")

    fixture_types: dict[str, Counter[str]] = {}
    for row in fixture_rows:
        fixture_types.setdefault(row.get("case_id", ""), Counter())[row.get("fixture_type", "")] += 1
    expected_types = Counter({"good_handling": 1, "failure_mode": 1})
    bad_pairs = sorted(case_id for case_id, counts in fixture_types.items() if counts != expected_types)
    if bad_pairs or len(fixture_types) != len(case_rows):
        errors.append(f"CASE_FIXTURE_PAIR_MISMATCH: {bad_pairs}")

    if _jsonl_rows(ROOT / "data/replayops_cases.jsonl") != case_rows:
        errors.append("CASE_JSONL_NOT_EQUIVALENT")
    if _jsonl_rows(ROOT / "data/fixture_traces.jsonl") != fixture_rows:
        errors.append("FIXTURE_JSONL_NOT_EQUIVALENT")

    cases_metadata = json.loads((ROOT / "data/replayops_cases_metadata.json").read_text())
    fixtures_metadata = json.loads((ROOT / "data/fixture_traces_metadata.json").read_text())
    expected_cases_metadata = {key: value for key, value in cases_payload.items() if key != "cases"}
    expected_fixtures_metadata = {
        key: value for key, value in fixtures_payload.items() if key != "fixtures"
    }
    if cases_metadata != expected_cases_metadata:
        errors.append("CASE_METADATA_NOT_CANONICAL_SIDECAR")
    if fixtures_metadata != expected_fixtures_metadata:
        errors.append("FIXTURE_METADATA_NOT_CANONICAL_SIDECAR")

    return errors


def _validate_versions(manifest: dict) -> list[str]:
    errors: list[str] = []
    release_version = manifest["release_version"]
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if pyproject["project"]["version"] != release_version:
        errors.append("PYPROJECT_RELEASE_VERSION_MISMATCH")

    cff_text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    cff_match = re.search(r'^version:\s*["\']?([^"\'\n]+)', cff_text, re.MULTILINE)
    if not cff_match or cff_match.group(1).strip() != release_version:
        errors.append("CFF_RELEASE_VERSION_MISMATCH")
    return errors


def validate_current_tree() -> tuple[list[str], int]:
    manifest = load_manifest()
    paths = repository_paths()
    path_set = set(paths)
    errors: list[str] = []

    missing = sorted(set(manifest["required_paths"]) - path_set)
    for path in missing:
        errors.append(f"MISSING_REQUIRED_PATH: {path}")
    if manifest.get("enforce_exact_path_set"):
        undeclared = sorted(path_set - set(manifest["required_paths"]))
        for path in undeclared:
            errors.append(f"UNDECLARED_PATH: {path}")

    for path in paths:
        if path_is_forbidden(path, manifest["forbidden_tracked_globs"]):
            errors.append(f"FORBIDDEN_PATH: {path}")
        full_path = ROOT / path
        if full_path.is_symlink():
            errors.append(f"SYMLINK_NOT_ALLOWED: {path}")
            continue
        if not full_path.is_file():
            continue
        if full_path.stat().st_size > manifest["max_text_scan_bytes"]:
            errors.append(f"OVERSIZED_FILE_NOT_ALLOWED: {path}")
            continue
        raw = full_path.read_bytes()
        if b"\x00" in raw:
            errors.append(f"BINARY_FILE_NOT_ALLOWED: {path}")
            continue
        text = raw.decode("utf-8", errors="ignore")
        errors.extend(
            scan_text(
                text,
                path,
                manifest["forbidden_literals"],
                skip_policy_literals=path == MANIFEST_RELPATH,
            )
        )

    errors.extend(_validate_dataset(manifest))
    errors.extend(_validate_versions(manifest))
    return errors, len(paths)


def main() -> int:
    errors, path_count = validate_current_tree()
    if errors:
        print("PUBLIC_TREE_CHECK_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PUBLIC_TREE_CHECK_OK paths={path_count} cases=26 fixtures=52")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
