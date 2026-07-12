"""Public research artifact documentation checks."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_release_docs_exist():
    for name in (
        "README.md",
        "SAFETY_POLICY.md",
        "DATASET_CARD.md",
        "EVALUATION_CARD.md",
        "SCHEMA.md",
        "LIMITATIONS.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CITATION.cff",
        "CONTRIBUTING.md",
        "release/public_release_manifest.json",
        "huggingface/README.md",
    ):
        assert (ROOT / name).exists(), f"missing {name}"


def test_safety_policy_states_non_capability_boundary():
    text = (ROOT / "SAFETY_POLICY.md").read_text()
    assert "does not evaluate biological capability" in text
    assert "no live model evaluation" in text
    assert "Only records with `release_split: \"public\"`" in text


def test_dataset_card_states_fixture_and_non_leaderboard_boundaries():
    text = (ROOT / "DATASET_CARD.md").read_text()
    assert "model leaderboard" in text
    assert "Cases | 26" in text
    assert "Fixtures | 52" in text
    assert "synthetic `private_reviewer_note_content`" in text


def test_schema_documents_multilabel_failure_modes():
    text = (ROOT / "SCHEMA.md").read_text()
    assert "Top-Level Payloads" in text
    assert "`failure_modes` is a list" in text
    assert "prompt_injection_followed" in text
    assert "hard_gate_pass" in text
    assert "derived_audit_findings" in text


def test_limitations_preserve_claim_boundary():
    text = (ROOT / "LIMITATIONS.md").read_text().casefold()
    assert "fixture validation, not model evaluation" in text
    assert "does not prove that a model will behave safely" in text


def test_release_manifest_has_one_current_identity():
    manifest = json.loads((ROOT / "release/public_release_manifest.json").read_text())
    assert manifest["release_version"] == "0.2.0"
    assert manifest["dataset_schema_version"] == "0.1.6"
    assert manifest["expected_counts"] == {"cases": 26, "fixtures": 52, "hard_gates": 9}
    assert manifest["enforce_exact_path_set"] is True
    assert "releases/**" in manifest["forbidden_tracked_globs"]
    assert "data/_private/**" in manifest["forbidden_tracked_globs"]


def test_hugging_face_card_declares_both_configs():
    text = (ROOT / "huggingface/README.md").read_text()
    assert "config_name: cases" in text
    assert "config_name: fixtures" in text
    assert "data/replayops_cases.jsonl" in text
    assert "data/fixture_traces.jsonl" in text
