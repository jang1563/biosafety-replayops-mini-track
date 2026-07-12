"""Schema tests for the ReplayOps public 26-case dataset (v0.1.6)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from biosafety_replayops.schema import ReplayOpsLoader

ROOT = Path(__file__).resolve().parents[1]


def test_loader_validates_without_errors():
    loader = ReplayOpsLoader.from_root(ROOT)
    assert loader.validate() == []


def test_dataset_has_twenty_six_public_cases_and_fifty_two_fixtures():
    loader = ReplayOpsLoader.from_root(ROOT)
    assert len(loader.cases()) == 26
    assert len(loader.fixtures()) == 52


def test_each_case_has_review_action_item_fields():
    loader = ReplayOpsLoader.from_root(ROOT)
    required = {
        "legitimate_help_target",
        "review_context_required",
        "policy_anchor_confidence",
        "expert_disagreement_level",
        "public_response_allowed",
        "private_reviewer_note_allowed",
        "untrusted_instruction_present",
        "untrusted_instruction_type",
        "factual_content_from_untrusted_allowed",
        "policy_instruction_from_untrusted_forbidden",
        "tool_call_attempted",
        "tool_call_block_reason",
        "must_log_route",
        "required_tool_calls",
        "required_audit_events",
        "forbidden_tool_calls",
    }
    for case_id, case in loader.cases().items():
        missing = required - set(case)
        assert not missing, f"{case_id} missing {sorted(missing)}"


def test_failure_modes_are_multilabel_lists():
    loader = ReplayOpsLoader.from_root(ROOT)
    for fixture in loader.fixtures():
        assert isinstance(fixture["failure_modes"], list)
        assert fixture["failure_modes"]
        assert "failure_mode" not in fixture


def test_dataset_covers_required_case_families():
    loader = ReplayOpsLoader.from_root(ROOT)
    found = {case["scenario_family"] for case in loader.cases().values()}
    expected = {
        "legitimate_literature_triage",
        "false_refusal_probe",
        "missing_context_clarification",
        "prompt_injected_retrieval",
        "human_gate_tool_action",
        "benign_data_interpretation",
        "method_comparison_high_level",
        "policy_boundary_ambiguity",
        "unsafe_pass_probe",
        "replay_drift_case",
        "reviewer_disclosure_attack",
        "provenance_integrity_attack",
    }
    assert found == expected


def test_dataset_covers_taxonomy_aligned_injection_classes():
    loader = ReplayOpsLoader.from_root(ROOT)
    found = {
        case["untrusted_instruction_type"]
        for case in loader.cases().values()
        if case["untrusted_instruction_present"]
    }
    expected = {
        "logging_suppression",
        "route_forcing",
        "fabricated_authority",
        "human_gate_bypass",
        "instruction_override",
        "context_distraction",
        "audit_evasion_attempt",
        "eval_gaming_attempt",
        "reviewer_role_spoofing",
        "reviewer_note_disclosure_attempt",
        "provenance_falsification_attempt",
    }
    assert expected <= found


def test_all_cases_declare_release_split():
    loader = ReplayOpsLoader.from_root(ROOT)
    for case_id, case in loader.cases().items():
        assert case.get("release_split") == "public", (
            f"{case_id} release_split should be 'public' for v0.1.5 release"
        )


def test_v015_release_split_field_present_on_new_cases():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    assert "replayops_023" in cases
    assert "replayops_024" in cases
    assert cases["replayops_023"]["release_split"] == "public"
    assert cases["replayops_024"]["release_split"] == "public"


def test_v015_disclosure_cases_carry_note_content_and_constraint():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    for case_id in ("replayops_023", "replayops_024"):
        case = cases[case_id]
        assert case["review_context_required"] is True
        assert case["public_response_constraint"] in {"open", "reviewer_only"}
        assert isinstance(case.get("private_reviewer_note_content"), str)
        assert case["private_reviewer_note_content"]


def test_v015_existing_cases_have_null_disclosure_fields():
    loader = ReplayOpsLoader.from_root(ROOT)
    for case_id, case in loader.cases().items():
        if case_id in {"replayops_023", "replayops_024"}:
            continue
        assert case.get("public_response_constraint") is None, case_id
        assert case.get("private_reviewer_note_content") is None, case_id


def test_v016_provenance_cases_carry_expected_provenance():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    for case_id in ("replayops_025", "replayops_026"):
        case = cases[case_id]
        assert case["scenario_family"] == "provenance_integrity_attack"
        assert isinstance(case.get("expected_provenance"), dict)
        assert case["expected_provenance"].get("observed_policy_anchors_subset_of")


def test_v016_existing_cases_have_null_provenance_and_canary_fields():
    loader = ReplayOpsLoader.from_root(ROOT)
    for case_id, case in loader.cases().items():
        if case_id in {"replayops_025", "replayops_026"}:
            continue
        assert case.get("expected_provenance") is None, case_id
        assert case.get("canary_signature") is None, case_id


def test_v016_public_split_contains_no_canary_or_private():
    loader = ReplayOpsLoader.from_root(ROOT)
    for case_id, case in loader.cases().items():
        assert case.get("release_split") == "public", case_id
        assert case.get("canary_signature") is None, case_id


def test_drift_fixtures_carry_prior_replay_records():
    loader = ReplayOpsLoader.from_root(ROOT)
    cases = loader.cases()
    drift_fixtures = [
        fixture
        for fixture in loader.fixtures()
        if cases[fixture["case_id"]]["scenario_family"] == "replay_drift_case"
    ]
    assert len(drift_fixtures) == 6, "expected 3 drift cases x 2 fixtures"
    for fixture in drift_fixtures:
        assert fixture.get("prior_replay_records"), (
            f"{fixture['fixture_id']} drift fixture missing prior_replay_records"
        )
        assert fixture.get("replay_status") in {
            "drift_resolved",
            "drift_consistent",
            "drift_resolved_late",
            "regression_introduced",
            "drift_unresolved",
        }, f"{fixture['fixture_id']} drift fixture has unexpected replay_status"


def test_dataset_covers_v012_ambiguity_types():
    loader = ReplayOpsLoader.from_root(ROOT)
    found = {case["ambiguity_type"] for case in loader.cases().values()}
    new_axes = {"institution_missing", "operationality_unclear", "expert_disagreement"}
    assert new_axes <= found


def test_dataset_route_diversity_includes_allow_and_refuse():
    loader = ReplayOpsLoader.from_root(ROOT)
    expected_routes = {case["expected_route"] for case in loader.cases().values()}
    assert {"allow", "caveat", "clarify", "escalate", "refuse"} == expected_routes


def test_schema_rejects_case_fixture_version_mismatch(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    fixtures_payload["fixtures"][0]["case_version"] = "0.0.0"
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("case_version does not match case" in error for error in errors)


def test_schema_rejects_top_level_dataset_name_mismatch(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    cases_payload["dataset_name"] = "Wrong Dataset"
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("cases payload dataset_name mismatch" in error for error in errors)


def test_schema_rejects_top_level_schema_version_mismatch(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    fixtures_payload["schema_version"] = "0.0.0"
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("fixtures payload schema_version mismatch" in error for error in errors)
    assert any("Top-level schema_version mismatch" in error for error in errors)


def test_schema_requires_fixture_batch_id(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    del fixtures_payload["fixture_batch_id"]
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("fixtures payload missing top-level field fixture_batch_id" in error for error in errors)


def test_schema_rejects_none_combined_with_failure_modes(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    fixtures_payload["fixtures"][1]["failure_modes"] = ["none", "overconfident_answer"]
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("cannot be combined" in error for error in errors)


def test_schema_rejects_malformed_context_item(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    del cases_payload["cases"][0]["trusted_context"][0]["context_id"]
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("trusted_context[0] missing context_id" in error for error in errors)


def test_schema_requires_tool_policy_fields(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    del cases_payload["cases"][0]["required_tool_calls"]
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("missing case field required_tool_calls" in error for error in errors)


def test_schema_requires_audit_event_fields(tmp_path: Path):
    cases_payload, fixtures_payload = _payloads()
    del cases_payload["cases"][0]["required_audit_events"]
    errors = _loader(tmp_path, cases_payload, fixtures_payload).validate()
    assert any("missing case field required_audit_events" in error for error in errors)


def _payloads() -> tuple[dict, dict]:
    loader = ReplayOpsLoader.from_root(ROOT)
    return copy.deepcopy(loader.load_cases_payload()), copy.deepcopy(loader.load_fixtures_payload())


def _loader(
    tmp_path: Path, cases_payload: dict, fixtures_payload: dict
) -> ReplayOpsLoader:
    cases_path = tmp_path / "cases.json"
    fixtures_path = tmp_path / "fixtures.json"
    cases_path.write_text(json.dumps(cases_payload))
    fixtures_path.write_text(json.dumps(fixtures_payload))
    return ReplayOpsLoader(cases_path, fixtures_path)
