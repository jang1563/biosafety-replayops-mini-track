"""Schema loading and validation for the BioSafety ReplayOps mini-track."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROUTES = {"allow", "caveat", "clarify", "escalate", "refuse"}
RESPONSE_SHAPES = {
    "normal_answer",
    "bounded_answer",
    "clarifying_question",
    "escalation_notice",
    "refusal",
}
FIXTURE_TYPES = {"good_handling", "failure_mode"}
FAILURE_MODES = {
    "none",
    "false_refusal",
    "unsafe_pass",
    "wrong_clarification",
    "missed_clarification",
    "wrong_escalation",
    "missed_escalation",
    "prompt_injection_followed",
    "unauthorized_tool_action",
    "policy_anchor_mismatch",
    "replay_export_missing",
    "overconfident_answer",
    "regression_introduced",
    "drift_unresolved",
    "public_disclosure_violation",
    "reviewer_note_leak",
    "provenance_anchor_fabrication",
    "failure_mode_self_erasure",
}
SOURCE_SEEDS = {"synthetic", "biosafety_case_bench"}
SCENARIO_FAMILIES = {
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
TOOL_SURFACES = {
    "literature_metadata_stub",
    "chat_only",
    "policy_lookup_stub",
    "retrieval_stub",
    "human_gate_stub",
}
AMBIGUITY_TYPES = {
    "none",
    "dual_use_surface_form",
    "purpose_missing",
    "source_trust_conflict",
    "consequential_action",
    "institution_missing",
    "operationality_unclear",
    "expert_disagreement",
}
CONFIDENCE_LEVELS = {"low", "medium", "high"}
EXPERT_DISAGREEMENT_LEVELS = {"low", "medium", "high"}
UNTRUSTED_INSTRUCTION_TYPES = {
    None,
    "logging_suppression",
    "instruction_override",
    "route_forcing",
    "fabricated_authority",
    "human_gate_bypass",
    "context_distraction",
    "audit_evasion_attempt",
    "eval_gaming_attempt",
    "reviewer_role_spoofing",
    "reviewer_note_disclosure_attempt",
    "provenance_falsification_attempt",
}
RELEASE_SPLITS = {"public", "private", "canary"}
PUBLIC_RESPONSE_CONSTRAINTS = {None, "open", "reviewer_only"}
REPLAY_STATUSES = {
    "not_run",
    "drift_consistent",
    "drift_resolved",
    "drift_resolved_late",
    "regression_introduced",
    "drift_unresolved",
}
TRUSTED_CONTEXT_FIELDS = {"context_id", "kind", "summary"}
UNTRUSTED_CONTEXT_FIELDS = {"context_id", "kind", "summary", "injection_class"}
EXPECTED_DATASET_NAME = "BioSafety ReplayOps Mini-Track"
SCHEMA_VERSION = "0.1.6"

REQUIRED_CASE_PAYLOAD_FIELDS = {
    "dataset_name",
    "schema_version",
    "route_vocab",
    "response_shape_vocab",
    "cases",
}
REQUIRED_FIXTURE_PAYLOAD_FIELDS = {
    "dataset_name",
    "schema_version",
    "fixture_batch_id",
    "fixtures",
}

REQUIRED_CASE_FIELDS = {
    "case_id",
    "case_version",
    "source_project",
    "source_seed",
    "scenario_family",
    "turn_count",
    "tool_surface",
    "user_goal_summary",
    "legitimate_help_target",
    "trusted_context",
    "untrusted_context",
    "ambiguity_type",
    "expected_route",
    "acceptable_route_set",
    "expected_response_shape",
    "policy_anchors",
    "policy_anchor_confidence",
    "expert_disagreement_level",
    "review_context_required",
    "public_response_allowed",
    "private_reviewer_note_allowed",
    "human_gate_required",
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
    "forbidden_response_features",
    "notes_public_safe",
    "release_split",
    "public_response_constraint",
    "private_reviewer_note_content",
    "expected_provenance",
    "canary_signature",
}

REQUIRED_FIXTURE_FIELDS = {
    "fixture_id",
    "case_id",
    "fixture_type",
    "messages",
    "tool_calls_requested",
    "tool_calls_approved",
    "tool_calls_blocked",
    "observed_route",
    "observed_response_shape",
    "observed_policy_anchors",
    "human_gate_observed",
    "unauthorized_tool_action",
    "failure_modes",
    "case_version",
    "model_version",
    "router_version",
    "policy_version",
    "replay_batch_id",
}


class ValidationError(ValueError):
    """Raised when ReplayOps data fails structural validation."""


@dataclass(frozen=True)
class ReplayOpsLoader:
    """Load and validate ReplayOps cases and fixture traces."""

    cases_path: Path
    fixtures_path: Path

    @classmethod
    def from_root(cls, root: Path) -> "ReplayOpsLoader":
        return cls(root / "data" / "replayops_cases.json", root / "data" / "fixture_traces.json")

    def load_cases_payload(self) -> dict[str, Any]:
        return json.loads(self.cases_path.read_text())

    def load_fixtures_payload(self) -> dict[str, Any]:
        return json.loads(self.fixtures_path.read_text())

    def cases(self) -> dict[str, dict[str, Any]]:
        payload = self.load_cases_payload()
        return {case["case_id"]: case for case in payload["cases"]}

    def fixtures(self) -> list[dict[str, Any]]:
        return self.load_fixtures_payload()["fixtures"]

    def validate(self) -> list[str]:
        errors: list[str] = []
        cases_payload = self.load_cases_payload()
        fixtures_payload = self.load_fixtures_payload()

        errors.extend(_validate_cases_payload(cases_payload))
        errors.extend(_validate_fixtures_payload(fixtures_payload))
        if (
            cases_payload.get("schema_version") is not None
            and fixtures_payload.get("schema_version") is not None
            and cases_payload.get("schema_version") != fixtures_payload.get("schema_version")
        ):
            errors.append("Top-level schema_version mismatch between cases and fixtures")

        cases = cases_payload.get("cases", [])
        fixtures = fixtures_payload.get("fixtures", [])
        if not isinstance(cases, list):
            cases = []
        if not isinstance(fixtures, list):
            fixtures = []
        case_ids = [case.get("case_id") for case in cases]

        if len(case_ids) != len(set(case_ids)):
            errors.append("Duplicate case_id found")

        for case in cases:
            errors.extend(_validate_case(case))

        cases_by_id = {case["case_id"]: case for case in cases if "case_id" in case}
        fixture_ids = [fixture.get("fixture_id") for fixture in fixtures]
        if len(fixture_ids) != len(set(fixture_ids)):
            errors.append("Duplicate fixture_id found")

        fixtures_by_case: dict[str, list[str]] = {}
        for fixture in fixtures:
            errors.extend(_validate_fixture(fixture, cases_by_id))
            fixtures_by_case.setdefault(fixture.get("case_id", ""), []).append(
                fixture.get("fixture_type", "")
            )

        for case_id in case_ids:
            found_types = sorted(fixtures_by_case.get(case_id, []))
            if found_types != ["failure_mode", "good_handling"]:
                errors.append(f"{case_id}: expected one good_handling and one failure_mode fixture")

        return errors

    def validate_or_raise(self) -> None:
        errors = self.validate()
        if errors:
            raise ValidationError("\n".join(errors))


def _validate_case(case: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    case_id = case.get("case_id", "<missing-case-id>")
    missing = sorted(REQUIRED_CASE_FIELDS - set(case))
    for field in missing:
        errors.append(f"{case_id}: missing case field {field}")

    expected_route = case.get("expected_route")
    if expected_route not in ROUTES:
        errors.append(f"{case_id}: invalid expected_route {expected_route!r}")

    if case.get("source_seed") not in SOURCE_SEEDS:
        errors.append(f"{case_id}: invalid source_seed")

    if case.get("scenario_family") not in SCENARIO_FAMILIES:
        errors.append(f"{case_id}: invalid scenario_family")

    if case.get("tool_surface") not in TOOL_SURFACES:
        errors.append(f"{case_id}: invalid tool_surface")

    if case.get("ambiguity_type") not in AMBIGUITY_TYPES:
        errors.append(f"{case_id}: invalid ambiguity_type")

    if case.get("policy_anchor_confidence") not in CONFIDENCE_LEVELS:
        errors.append(f"{case_id}: invalid policy_anchor_confidence")

    if case.get("expert_disagreement_level") not in EXPERT_DISAGREEMENT_LEVELS:
        errors.append(f"{case_id}: invalid expert_disagreement_level")

    if case.get("release_split") not in RELEASE_SPLITS:
        errors.append(f"{case_id}: invalid release_split")

    public_response_constraint = case.get("public_response_constraint")
    if public_response_constraint not in PUBLIC_RESPONSE_CONSTRAINTS:
        errors.append(f"{case_id}: invalid public_response_constraint")

    note_content = case.get("private_reviewer_note_content")
    if note_content is not None and not isinstance(note_content, str):
        errors.append(f"{case_id}: private_reviewer_note_content must be string or null")
    if (
        case.get("review_context_required") is False
        and note_content is not None
        and note_content != ""
    ):
        errors.append(
            f"{case_id}: private_reviewer_note_content must be null when review_context_required is false"
        )

    expected_provenance = case.get("expected_provenance")
    if expected_provenance is not None:
        if not isinstance(expected_provenance, dict):
            errors.append(f"{case_id}: expected_provenance must be dict or null")
        else:
            for sub_field in (
                "observed_policy_anchors_subset_of",
                "evidence_must_reference_only",
                "failure_modes_must_include_when_gate_triggers",
            ):
                value = expected_provenance.get(sub_field)
                if value is not None and not isinstance(value, list):
                    errors.append(
                        f"{case_id}: expected_provenance.{sub_field} must be list or null"
                    )

    canary_signature = case.get("canary_signature")
    release_split = case.get("release_split")
    if canary_signature is not None and not isinstance(canary_signature, str):
        errors.append(f"{case_id}: canary_signature must be string or null")
    if release_split == "canary" and not canary_signature:
        errors.append(
            f"{case_id}: canary_signature must be non-empty when release_split is canary"
        )
    if release_split != "canary" and canary_signature is not None:
        errors.append(
            f"{case_id}: canary_signature must be null when release_split is not canary"
        )

    acceptable = case.get("acceptable_route_set", [])
    if not isinstance(acceptable, list) or not acceptable:
        errors.append(f"{case_id}: acceptable_route_set must be a non-empty list")
    elif any(route not in ROUTES for route in acceptable):
        errors.append(f"{case_id}: acceptable_route_set contains invalid route")
    elif expected_route not in acceptable:
        errors.append(f"{case_id}: expected_route must be in acceptable_route_set")

    if case.get("expected_response_shape") not in RESPONSE_SHAPES:
        errors.append(f"{case_id}: invalid expected_response_shape")

    for list_field in (
        "trusted_context",
        "untrusted_context",
        "policy_anchors",
        "required_tool_calls",
        "required_audit_events",
        "forbidden_tool_calls",
        "forbidden_response_features",
    ):
        if not isinstance(case.get(list_field), list):
            errors.append(f"{case_id}: {list_field} must be a list")
        elif any(not isinstance(item, str) for item in case.get(list_field, [])) and list_field not in {
            "trusted_context",
            "untrusted_context",
        }:
            errors.append(f"{case_id}: {list_field} entries must be strings")

    for bool_field in (
        "review_context_required",
        "public_response_allowed",
        "private_reviewer_note_allowed",
        "human_gate_required",
        "untrusted_instruction_present",
        "factual_content_from_untrusted_allowed",
        "policy_instruction_from_untrusted_forbidden",
        "tool_call_attempted",
        "must_log_route",
    ):
        if not isinstance(case.get(bool_field), bool):
            errors.append(f"{case_id}: {bool_field} must be boolean")

    instruction_type = case.get("untrusted_instruction_type")
    if instruction_type not in UNTRUSTED_INSTRUCTION_TYPES:
        errors.append(f"{case_id}: invalid untrusted_instruction_type")
    if case.get("untrusted_instruction_present") is False and instruction_type is not None:
        errors.append(f"{case_id}: untrusted_instruction_type must be null when absent")
    if case.get("untrusted_instruction_present") is True and instruction_type is None:
        errors.append(f"{case_id}: untrusted_instruction_type required when present")

    errors.extend(
        _validate_context_items(
            case_id, "trusted_context", case.get("trusted_context", []), TRUSTED_CONTEXT_FIELDS
        )
    )
    errors.extend(
        _validate_context_items(
            case_id,
            "untrusted_context",
            case.get("untrusted_context", []),
            UNTRUSTED_CONTEXT_FIELDS,
        )
    )

    return errors


def _validate_cases_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_CASE_PAYLOAD_FIELDS - set(payload))
    for field in missing:
        errors.append(f"cases payload missing top-level field {field}")

    if payload.get("dataset_name") != EXPECTED_DATASET_NAME:
        errors.append("cases payload dataset_name mismatch")

    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append("cases payload schema_version mismatch")

    route_vocab = payload.get("route_vocab")
    if not isinstance(route_vocab, list) or set(route_vocab) != ROUTES:
        errors.append("cases payload route_vocab mismatch")

    response_shape_vocab = payload.get("response_shape_vocab")
    if not isinstance(response_shape_vocab, list) or set(response_shape_vocab) != RESPONSE_SHAPES:
        errors.append("cases payload response_shape_vocab mismatch")

    if not isinstance(payload.get("cases"), list):
        errors.append("cases payload cases must be a list")

    return errors


def _validate_fixtures_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_FIXTURE_PAYLOAD_FIELDS - set(payload))
    for field in missing:
        errors.append(f"fixtures payload missing top-level field {field}")

    if payload.get("dataset_name") != EXPECTED_DATASET_NAME:
        errors.append("fixtures payload dataset_name mismatch")

    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append("fixtures payload schema_version mismatch")

    fixture_batch_id = payload.get("fixture_batch_id")
    if not isinstance(fixture_batch_id, str) or not fixture_batch_id:
        errors.append("fixtures payload fixture_batch_id must be a non-empty string")

    if not isinstance(payload.get("fixtures"), list):
        errors.append("fixtures payload fixtures must be a list")

    return errors


def _validate_fixture(
    fixture: dict[str, Any], cases_by_id: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    fixture_id = fixture.get("fixture_id", "<missing-fixture-id>")
    missing = sorted(REQUIRED_FIXTURE_FIELDS - set(fixture))
    for field in missing:
        errors.append(f"{fixture_id}: missing fixture field {field}")

    case_id = fixture.get("case_id")
    if case_id not in cases_by_id:
        errors.append(f"{fixture_id}: unknown case_id {case_id!r}")
    else:
        case = cases_by_id[case_id]
        if fixture.get("case_version") != case.get("case_version"):
            errors.append(f"{fixture_id}: case_version does not match case")

    if fixture.get("fixture_type") not in FIXTURE_TYPES:
        errors.append(f"{fixture_id}: invalid fixture_type")

    if fixture.get("observed_route") not in ROUTES:
        errors.append(f"{fixture_id}: invalid observed_route")

    if fixture.get("observed_response_shape") not in RESPONSE_SHAPES:
        errors.append(f"{fixture_id}: invalid observed_response_shape")

    messages = fixture.get("messages", [])
    if not isinstance(messages, list) or len(messages) != 2:
        errors.append(f"{fixture_id}: expected exactly two messages")
    else:
        roles = [msg.get("role") for msg in messages]
        if roles != ["user", "assistant"]:
            errors.append(f"{fixture_id}: expected user then assistant messages")

    failure_modes = fixture.get("failure_modes", [])
    if not isinstance(failure_modes, list) or not failure_modes:
        errors.append(f"{fixture_id}: failure_modes must be a non-empty list")
    elif any(mode not in FAILURE_MODES for mode in failure_modes):
        errors.append(f"{fixture_id}: failure_modes contains invalid mode")
    elif "none" in failure_modes and failure_modes != ["none"]:
        errors.append(f"{fixture_id}: failure_modes ['none'] cannot be combined")

    if fixture.get("fixture_type") == "good_handling" and failure_modes != ["none"]:
        errors.append(f"{fixture_id}: good_handling fixture must have failure_modes ['none']")

    if fixture.get("fixture_type") == "failure_mode" and failure_modes == ["none"]:
        errors.append(f"{fixture_id}: failure_mode fixture must not have only ['none']")

    for list_field in (
        "tool_calls_requested",
        "tool_calls_approved",
        "tool_calls_blocked",
        "observed_policy_anchors",
    ):
        if not isinstance(fixture.get(list_field), list):
            errors.append(f"{fixture_id}: {list_field} must be a list")
        elif any(not isinstance(item, str) for item in fixture.get(list_field, [])):
            errors.append(f"{fixture_id}: {list_field} entries must be strings")

    if "replay_status" in fixture and fixture["replay_status"] not in REPLAY_STATUSES:
        errors.append(f"{fixture_id}: invalid replay_status")

    prior_records = fixture.get("prior_replay_records")
    if prior_records is not None:
        if not isinstance(prior_records, list):
            errors.append(f"{fixture_id}: prior_replay_records must be a list or null")
        else:
            for index, record in enumerate(prior_records):
                if not isinstance(record, dict):
                    errors.append(
                        f"{fixture_id}: prior_replay_records[{index}] must be an object"
                    )
                    continue
                required_record_fields = {
                    "router_version",
                    "policy_version",
                    "model_version",
                    "observed_route",
                    "observed_response_shape",
                    "failure_modes",
                    "replay_status",
                }
                missing = sorted(required_record_fields - set(record))
                for field in missing:
                    errors.append(
                        f"{fixture_id}: prior_replay_records[{index}] missing {field}"
                    )
                if record.get("replay_status") not in REPLAY_STATUSES:
                    errors.append(
                        f"{fixture_id}: prior_replay_records[{index}] invalid replay_status"
                    )
                if record.get("observed_route") not in ROUTES:
                    errors.append(
                        f"{fixture_id}: prior_replay_records[{index}] invalid observed_route"
                    )
                if record.get("observed_response_shape") not in RESPONSE_SHAPES:
                    errors.append(
                        f"{fixture_id}: prior_replay_records[{index}] invalid observed_response_shape"
                    )

    return errors


def _validate_context_items(
    case_id: str, field_name: str, items: Any, required_fields: set[str]
) -> list[str]:
    errors: list[str] = []
    if not isinstance(items, list):
        return errors
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{case_id}: {field_name}[{index}] must be an object")
            continue
        missing = sorted(required_fields - set(item))
        for field in missing:
            errors.append(f"{case_id}: {field_name}[{index}] missing {field}")
        for field in required_fields:
            if field in item and field != "injection_class" and not isinstance(item[field], str):
                errors.append(f"{case_id}: {field_name}[{index}].{field} must be string")
        if "injection_class" in item and item["injection_class"] is not None and not isinstance(
            item["injection_class"], str
        ):
            errors.append(f"{case_id}: {field_name}[{index}].injection_class must be string or null")
    return errors
