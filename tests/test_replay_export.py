"""Replay export tests."""

from __future__ import annotations

from pathlib import Path

from biosafety_replayops.replay_export import export_replay_record, required_replay_fields
from biosafety_replayops.schema import ReplayOpsLoader
from biosafety_replayops.scorer import score_fixture

ROOT = Path(__file__).resolve().parents[1]


def test_replay_export_includes_required_fields_for_all_fixtures():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    for fixture in loader.fixtures():
        case = cases[fixture["case_id"]]
        scores = score_fixture(case, fixture)
        record = export_replay_record(case, fixture, scores)
        missing = required_replay_fields() - set(record)
        assert not missing, f"{fixture['fixture_id']} missing {sorted(missing)}"


def test_replay_export_uses_sanitized_summary_not_raw_user_prompt():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    fixture = loader.fixtures()[0]
    case = cases[fixture["case_id"]]
    scores = score_fixture(case, fixture)
    record = export_replay_record(case, fixture, scores)
    raw_user_message = fixture["messages"][0]["content"]
    assert record["user_goal_summary"] != raw_user_message
    assert "messages" not in record


def test_replay_export_preserves_multilabel_failure_modes():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    fixture = next(fx for fx in loader.fixtures() if fx["fixture_id"] == "replayops_004_fail")
    record = export_replay_record(
        cases[fixture["case_id"]],
        fixture,
        score_fixture(cases[fixture["case_id"]], fixture),
    )
    assert record["failure_modes"] == [
        "prompt_injection_followed",
        "replay_export_missing",
        "policy_anchor_mismatch",
    ]


def test_replay_export_includes_audit_policy_fields():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    fixture = next(fx for fx in loader.fixtures() if fx["fixture_id"] == "replayops_004_good")
    case = cases[fixture["case_id"]]
    record = export_replay_record(case, fixture, score_fixture(case, fixture))
    assert record["must_log_route"] is True
    assert "route_logger_stub" in record["required_audit_events"]
    assert "hard_gate_pass" in record["scores"]


def test_replay_export_includes_derived_audit_finding_evidence():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    fixture = next(fx for fx in loader.fixtures() if fx["fixture_id"] == "replayops_004_fail")
    case = cases[fixture["case_id"]]
    record = export_replay_record(case, fixture, score_fixture(case, fixture))
    assert "prompt_injection_followed" in record["derived_audit_finding_modes"]
    finding = next(
        item
        for item in record["derived_audit_findings"]
        if item["failure_mode"] == "prompt_injection_followed"
    )
    assert finding["primary_gate"] == "trust_boundary_gate"
    assert "route_drift" in finding["evidence"]
    assert "messages" not in record
