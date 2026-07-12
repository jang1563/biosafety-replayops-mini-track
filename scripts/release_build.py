#!/usr/bin/env python3
"""Fail-closed guard for a public release or upload-staging tree.

Verifies that a release-snapshot directory's ``data/`` subtree contains
only public cases — never the gitignored ``_private/`` or ``_canary/``
subdirectories. Fails loudly with a non-zero exit code when a private
or canary path is found, so the release-cut workflow cannot accidentally
ship held-out content in the public tarball.

Example::

    python scripts/release_build.py --check .hf_release

Set ``REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_FILE`` to a local, non-public
newline-delimited file of active canary strings to scan the snapshot for
content leaks without embedding those strings in this public script.
Alternatively, set ``REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_JSON`` to a
non-public ``replayops_cases.json`` file and the guard will extract
``canary_signature`` values from its cases.

This script is read-only. It does not create or modify any files.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

FORBIDDEN_PATH_NAMES = {"_private", "_canary"}
FORBIDDEN_RELEASE_SPLITS = {"private", "canary"}
IGNORED_DEVELOPMENT_PATH_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "build",
    "dist",
    "results",
}
FORBIDDEN_PUBLIC_STRINGS_FILE_ENV = "REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_FILE"
FORBIDDEN_PUBLIC_STRINGS_JSON_ENV = "REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_JSON"


def _iter_snapshot_paths(snapshot_root: Path):
    for path in snapshot_root.rglob("*"):
        relative = path.relative_to(snapshot_root)
        if any(part in IGNORED_DEVELOPMENT_PATH_NAMES for part in relative.parts):
            continue
        yield path


def _load_forbidden_public_strings() -> list[str]:
    path_value = os.environ.get(FORBIDDEN_PUBLIC_STRINGS_FILE_ENV)
    json_path_value = os.environ.get(FORBIDDEN_PUBLIC_STRINGS_JSON_ENV)
    strings: list[str] = []

    if path_value:
        path = Path(path_value).expanduser()
        try:
            strings.extend(
                line.strip()
                for line in path.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        except OSError as exc:
            strings.append(f"__UNREADABLE_FORBIDDEN_STRINGS_FILE__:{path}:{exc}")

    if json_path_value:
        path = Path(json_path_value).expanduser()
        try:
            payload = json.loads(path.read_text())
            strings.extend(
                case["canary_signature"]
                for case in payload.get("cases", [])
                if case.get("canary_signature")
            )
        except (json.JSONDecodeError, OSError) as exc:
            strings.append(f"__UNREADABLE_FORBIDDEN_STRINGS_FILE__:{path}:{exc}")

    return strings


def _scan_for_forbidden_public_strings(
    snapshot_root: Path, forbidden_strings: list[str]
) -> list[str]:
    if not forbidden_strings:
        return []

    unreadable_prefix = "__UNREADABLE_FORBIDDEN_STRINGS_FILE__:"
    unreadable = [s for s in forbidden_strings if s.startswith(unreadable_prefix)]
    if unreadable:
        return [
            value.replace(unreadable_prefix, "UNREADABLE_FORBIDDEN_STRINGS_FILE: ")
            for value in unreadable
        ]

    errors: list[str] = []
    for path in _iter_snapshot_paths(snapshot_root):
        if not path.is_file():
            continue
        try:
            content = path.read_text(errors="ignore")
        except OSError as exc:
            errors.append(f"UNREADABLE_SNAPSHOT_FILE: {path}: {exc}")
            continue
        for index, forbidden in enumerate(forbidden_strings):
            if forbidden and forbidden in content:
                errors.append(
                    "FORBIDDEN_PUBLIC_STRING_LEAK: "
                    f"{path.relative_to(snapshot_root)} token_index={index}"
                )
    return errors


def assert_release_split_consistency(snapshot_root: Path) -> list[str]:
    """Return a list of error messages; empty list means snapshot is clean.

    Two checks:

    1. No directory named ``_private`` or ``_canary`` may exist anywhere
       under the snapshot tree.
    2. Every ``replayops_cases.json`` under the snapshot must declare
       only ``release_split: "public"`` for its cases.
    3. When ``REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_FILE`` or
       ``REPLAYOPS_FORBIDDEN_PUBLIC_STRINGS_JSON`` is set, no listed
       active canary string may appear anywhere in the snapshot.
    """

    errors: list[str] = []

    for path in _iter_snapshot_paths(snapshot_root):
        if path.is_symlink():
            errors.append(f"SYMLINK_IN_SNAPSHOT: {path.relative_to(snapshot_root)}")
            continue
        if path.is_dir() and path.name in FORBIDDEN_PATH_NAMES:
            errors.append(
                f"FORBIDDEN_DIR_IN_SNAPSHOT: {path.relative_to(snapshot_root)}"
            )

    for cases_file in (
        path
        for path in _iter_snapshot_paths(snapshot_root)
        if path.is_file() and path.name == "replayops_cases.json"
    ):
        try:
            payload = json.loads(cases_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"UNREADABLE_CASES_FILE: {cases_file}: {exc}")
            continue
        cases = payload.get("cases") or []
        for case in cases:
            split = case.get("release_split")
            if split != "public":
                errors.append(
                    f"NON_PUBLIC_CASE_IN_SNAPSHOT: {cases_file.relative_to(snapshot_root)} "
                    f"case_id={case.get('case_id')!r} release_split={split!r}"
                )

    errors.extend(
        _scan_for_forbidden_public_strings(
            snapshot_root, _load_forbidden_public_strings()
        )
    )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, help="snapshot root directory")
    args = parser.parse_args()

    snapshot_root = Path(args.check).resolve()
    if not snapshot_root.exists():
        print(f"SNAPSHOT_ROOT_MISSING: {snapshot_root}")
        return 2

    errors = assert_release_split_consistency(snapshot_root)
    if errors:
        print("RELEASE_BUILD_GUARD_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("RELEASE_BUILD_GUARD_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
