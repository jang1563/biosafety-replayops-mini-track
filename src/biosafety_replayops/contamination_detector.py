"""Canary contamination detector for the schema 0.1.6 release-split track.

Loads the active canary signatures from ``data/_canary/replayops_cases.json``
when present and the retired canary signatures from
``data/_canary/retired_signatures.txt`` (added v0.1.6.3), normalizes
text via Unicode-NFKC, and exposes a deterministic substring-match
check that the scorer/report layer can call against any emitted text
(assistant response content, replay record fields).

The detector is intentionally substring-only. Paraphrase-robust detection
would require semantic similarity, which violates the project's
deterministic-only invariant. ``LIMITATIONS.md`` documents this scope.

The canary signatures are synthetic strings managed under the boundary in
``SAFETY_POLICY.md``. Active signature values and stable prefixes are not
printed in public artifacts. Retired signatures continue to be scanned so
previously seen contamination patterns remain detectable after rotation.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

CANARY_FILENAME = "_canary/replayops_cases.json"
RETIRED_SIGNATURES_FILENAME = "_canary/retired_signatures.txt"


def _normalize(text: str) -> str:
    """Unicode-NFKC normalization with case preserved.

    Canary detection is case-sensitive after normalization to avoid
    accidental matches on common biology vocabulary that overlaps with
    active canary tokens at lower case.
    """

    return unicodedata.normalize("NFKC", text)


def _load_retired_signatures(data_root: Path) -> list[str]:
    """Load retired canary signatures from
    ``data/_canary/retired_signatures.txt``.

    Format: one signature per line. Blank lines and lines beginning
    with ``#`` are ignored. Returns an empty list when the file is
    absent.
    """

    retired_path = Path(data_root) / RETIRED_SIGNATURES_FILENAME
    if not retired_path.exists():
        return []
    signatures: list[str] = []
    for raw_line in retired_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        signatures.append(_normalize(line))
    return signatures


def load_canary_signatures(data_root: Path) -> list[str]:
    """Load active + retired canary signatures from ``data/_canary/``.

    Returns the union of active signatures (from
    ``_canary/replayops_cases.json``) and retired signatures (from
    ``_canary/retired_signatures.txt``).

    Returns an empty list when the canary directory or files are
    absent (the public-release case). A controlled non-public validation
    environment may supply ``data/_canary/`` separately.
    """

    canary_path = Path(data_root) / CANARY_FILENAME
    signatures: list[str] = []
    if canary_path.exists():
        payload = json.loads(canary_path.read_text())
        cases = payload.get("cases") or []
        for case in cases:
            signature = case.get("canary_signature")
            if signature:
                signatures.append(_normalize(signature))
    signatures.extend(_load_retired_signatures(data_root))
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for sig in signatures:
        if sig not in seen:
            seen.add(sig)
            unique.append(sig)
    return unique


def detect_contamination(text: str, canary_signatures: list[str]) -> list[str]:
    """Return the list of canary signatures that substring-match ``text``.

    Detection is exact substring match after Unicode-NFKC normalization.
    Returns an empty list when ``canary_signatures`` is empty or when no
    match is found.
    """

    if not canary_signatures or not text:
        return []
    haystack = _normalize(text)
    return [signature for signature in canary_signatures if signature in haystack]


def scan_record_for_contamination(
    record: dict[str, Any], canary_signatures: list[str]
) -> dict[str, list[str]]:
    """Scan a replay record's text-bearing fields for canary substring matches.

    Returns a dict mapping field path to the list of matching signatures.
    Empty dict means clean. Currently scans:
      - ``user_goal_summary``
      - ``legitimate_help_target``
      - ``notes_public_safe``
      - ``derived_audit_findings[*].explanation``
      - ``derived_audit_findings[*].evidence`` (json-serialized)

    Reasoning traces are out of scope because the synthetic fixtures do not
    carry them.
    """

    if not canary_signatures:
        return {}

    hits: dict[str, list[str]] = {}
    for field in ("user_goal_summary", "legitimate_help_target", "notes_public_safe"):
        value = record.get(field)
        if isinstance(value, str):
            matches = detect_contamination(value, canary_signatures)
            if matches:
                hits[field] = matches

    findings = record.get("derived_audit_findings") or []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        explanation = finding.get("explanation")
        if isinstance(explanation, str):
            matches = detect_contamination(explanation, canary_signatures)
            if matches:
                hits[f"derived_audit_findings[{index}].explanation"] = matches
        evidence = finding.get("evidence")
        if evidence is not None:
            evidence_text = json.dumps(evidence, ensure_ascii=False)
            matches = detect_contamination(evidence_text, canary_signatures)
            if matches:
                hits[f"derived_audit_findings[{index}].evidence"] = matches

    return hits
