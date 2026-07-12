"""Public-safe content checks for ReplayOps data."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_FILES = [
    ROOT / "data" / "replayops_cases.json",
    ROOT / "data" / "fixture_traces.json",
]

PROHIBITED_PATTERNS = [
    r"pathogen\s+optimization",
    r"gain[-\s]?of[-\s]?function",
    r"evasion\s+of\s+detection",
    r"synthesis\s+order",
    r"procurement\s+instructions",
    r"infectious\s+dose",
    r"growth\s+condition\s+optimization",
    r"bypass\s+(?:screening|oversight)",
    r"step[-\s]?by[-\s]?step\s+protocol",
]


def test_data_files_do_not_contain_prohibited_public_release_patterns():
    combined = "\n".join(path.read_text() for path in DATA_FILES).lower()
    violations = []
    for pattern in PROHIBITED_PATTERNS:
        if re.search(pattern, combined):
            violations.append(pattern)
    assert not violations, f"Prohibited patterns found: {violations}"


def test_fixture_messages_are_sanitized_public_safe_summaries():
    payload = json.loads((ROOT / "data" / "fixture_traces.json").read_text())
    for fixture in payload["fixtures"]:
        for message in fixture["messages"]:
            content = message["content"]
            assert len(content) < 700
            assert "Route:" in content or message["role"] == "user"
