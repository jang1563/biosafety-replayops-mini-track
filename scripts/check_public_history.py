#!/usr/bin/env python3
"""Scan every reachable Git blob and commit for the public boundary."""

from __future__ import annotations

import re
import subprocess

from check_public_manifest import (
    ALLOWED_SERVICE_EMAILS,
    MANIFEST_RELPATH,
    ROOT,
    load_manifest,
    path_is_forbidden,
    scan_text,
)


def _git(*args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=text,
    )


def _validate_commit_metadata(forbidden_literals: list[str]) -> list[str]:
    errors: list[str] = []
    raw = _git(
        "log",
        "--format=%H%n%ae%n%ce%n%B%x00",
        "HEAD",
        "--branches",
        "--tags",
    ).stdout
    for record in raw.split("\x00"):
        lines = [line for line in record.strip().splitlines()]
        if len(lines) < 3:
            continue
        commit_sha, author_email, committer_email, *message_lines = lines
        for role, email in (("author", author_email), ("committer", committer_email)):
            if email not in ALLOWED_SERVICE_EMAILS and not email.endswith(
                "@users.noreply.github.com"
            ):
                errors.append(f"NON_NOREPLY_{role.upper()}: {commit_sha}: {email}")
        errors.extend(
            scan_text(
                "\n".join(message_lines),
                f"commit:{commit_sha}",
                forbidden_literals,
            )
        )
    return errors


def _validate_tag_metadata(forbidden_literals: list[str]) -> list[str]:
    errors: list[str] = []
    tags = _git("for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").stdout
    for line in tags.splitlines():
        object_id, object_type = line.split()
        if object_type != "tag":
            continue
        text = _git("cat-file", "tag", object_id).stdout
        match = re.search(r"^tagger .* <([^>]+)>", text, re.MULTILINE)
        if match and not match.group(1).endswith("@users.noreply.github.com"):
            errors.append(f"NON_NOREPLY_TAGGER: {object_id}: {match.group(1)}")
        message = text.split("\n\n", 1)[1] if "\n\n" in text else ""
        errors.extend(scan_text(message, f"tag:{object_id}", forbidden_literals))
    return errors


def validate_history() -> tuple[list[str], int]:
    manifest = load_manifest()
    errors: list[str] = []
    roots = [
        line
        for line in _git(
            "rev-list", "--max-parents=0", "HEAD", "--branches", "--tags"
        ).stdout.splitlines()
        if line
    ]
    if len(roots) != 1:
        errors.append(f"EXPECTED_ONE_HISTORY_ROOT: {len(roots)}")

    objects = _git("rev-list", "--objects", "HEAD", "--branches", "--tags").stdout.splitlines()
    scanned_blobs: set[str] = set()
    declared_paths = set(manifest["required_paths"])
    for line in objects:
        object_id, separator, path = line.partition(" ")
        if not separator or not path:
            continue
        object_type = _git("cat-file", "-t", object_id).stdout.strip()
        if object_type != "blob":
            continue
        if path_is_forbidden(path, manifest["forbidden_tracked_globs"]):
            errors.append(f"FORBIDDEN_HISTORY_PATH: {object_id}: {path}")
        if manifest.get("enforce_exact_path_set") and path not in declared_paths:
            errors.append(f"UNDECLARED_HISTORY_PATH: {object_id}: {path}")
        if object_id in scanned_blobs:
            continue
        scanned_blobs.add(object_id)
        size = int(_git("cat-file", "-s", object_id).stdout.strip())
        if size > manifest["max_text_scan_bytes"]:
            errors.append(f"OVERSIZED_HISTORY_BLOB: {object_id}: {path}")
            continue
        raw = _git("cat-file", "blob", object_id, text=False).stdout
        if b"\x00" in raw:
            errors.append(f"BINARY_HISTORY_BLOB: {object_id}: {path}")
            continue
        text = raw.decode("utf-8", errors="ignore")
        errors.extend(
            scan_text(
                text,
                f"blob:{object_id}:{path}",
                manifest["forbidden_literals"],
                skip_policy_literals=path == MANIFEST_RELPATH,
            )
        )

    errors.extend(_validate_commit_metadata(manifest["forbidden_literals"]))
    errors.extend(_validate_tag_metadata(manifest["forbidden_literals"]))
    return errors, len(scanned_blobs)


def main() -> int:
    errors, blob_count = validate_history()
    if errors:
        print("PUBLIC_HISTORY_CHECK_FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PUBLIC_HISTORY_CHECK_OK blobs={blob_count} roots=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
