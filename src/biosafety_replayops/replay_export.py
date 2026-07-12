"""Replay Ledger export helpers for ReplayOps fixtures."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .scorer import derive_observed_findings


def export_replay_record(
    case: dict[str, Any],
    fixture: dict[str, Any],
    scores: dict[str, float],
    derived_audit_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Export a sanitized Replay Ledger-compatible record."""

    if derived_audit_findings is None:
        derived_audit_findings = derive_observed_findings(case, fixture)
    derived_finding_modes = sorted(
        {finding["failure_mode"] for finding in derived_audit_findings}
    )

    note_content = case.get("private_reviewer_note_content")
    private_reviewer_note_content_hash = (
        hashlib.sha256(note_content.encode("utf-8")).hexdigest() if note_content else None
    )

    expected_provenance = case.get("expected_provenance")
    if expected_provenance:
        expected_provenance_canonical = json.dumps(
            expected_provenance, sort_keys=True, ensure_ascii=False
        )
        expected_provenance_hash = hashlib.sha256(
            expected_provenance_canonical.encode("utf-8")
        ).hexdigest()
    else:
        expected_provenance_hash = None

    canary_signature = case.get("canary_signature")
    canary_signature_hash = (
        hashlib.sha256(canary_signature.encode("utf-8")).hexdigest()
        if canary_signature
        else None
    )

    is_private_or_canary = case.get("release_split") in {"private", "canary"}

    return {
        "case_id": case["case_id"],
        "fixture_id": fixture["fixture_id"],
        "source_project": "biosafety_replayops",
        "ledger_version": "0.1.4",
        "case_version": fixture["case_version"],
        "scenario_family": case["scenario_family"],
        "user_goal_summary": case["user_goal_summary"],
        "legitimate_help_target": case["legitimate_help_target"],
        "tool_surface": case["tool_surface"],
        "must_log_route": case["must_log_route"],
        "required_tool_calls": case["required_tool_calls"],
        "required_audit_events": case["required_audit_events"],
        "forbidden_tool_calls": case["forbidden_tool_calls"],
        "trusted_context_ids": [ctx["context_id"] for ctx in case["trusted_context"]],
        "untrusted_context_ids": [ctx["context_id"] for ctx in case["untrusted_context"]],
        "expected_route": case["expected_route"],
        "acceptable_route_set": case["acceptable_route_set"],
        "observed_route": fixture["observed_route"],
        "expected_response_shape": case["expected_response_shape"],
        "observed_response_shape": fixture["observed_response_shape"],
        "policy_anchors_expected": case["policy_anchors"],
        "policy_anchors_observed": fixture["observed_policy_anchors"],
        "policy_anchor_confidence": case["policy_anchor_confidence"],
        "expert_disagreement_level": case["expert_disagreement_level"],
        "review_context_required": case["review_context_required"],
        "public_response_allowed": case["public_response_allowed"],
        "private_reviewer_note_allowed": case["private_reviewer_note_allowed"],
        "human_gate_required": case["human_gate_required"],
        "human_gate_observed": fixture["human_gate_observed"],
        "tool_calls_requested": fixture["tool_calls_requested"],
        "tool_calls_approved": fixture["tool_calls_approved"],
        "tool_calls_blocked": fixture["tool_calls_blocked"],
        "unauthorized_tool_action": fixture["unauthorized_tool_action"],
        "untrusted_instruction_present": case["untrusted_instruction_present"],
        "untrusted_instruction_type": case["untrusted_instruction_type"],
        "failure_modes": fixture["failure_modes"],
        "observed_failure_modes": derived_finding_modes,
        "derived_audit_finding_modes": derived_finding_modes,
        "derived_audit_findings": derived_audit_findings,
        "scores": scores,
        "replay_status": fixture.get("replay_status", "not_run"),
        "prior_replay_records": fixture.get("prior_replay_records", []) or [],
        "release_split": case.get("release_split", "public"),
        "public_response_constraint": case.get("public_response_constraint"),
        "private_reviewer_note_content_hash": private_reviewer_note_content_hash,
        "expected_provenance_hash": expected_provenance_hash,
        "canary_signature_hash": canary_signature_hash,
        "is_private_or_canary": is_private_or_canary,
        "model_version": fixture["model_version"],
        "router_version": fixture["router_version"],
        "policy_version": fixture["policy_version"],
        "replay_batch_id": fixture["replay_batch_id"],
        "notes_public_safe": case["notes_public_safe"],
    }


def required_replay_fields() -> set[str]:
    """Fields that every exported replay record must include."""

    return {
        "case_id",
        "fixture_id",
        "source_project",
        "ledger_version",
        "case_version",
        "scenario_family",
        "user_goal_summary",
        "legitimate_help_target",
        "tool_surface",
        "trusted_context_ids",
        "untrusted_context_ids",
        "expected_route",
        "acceptable_route_set",
        "observed_route",
        "expected_response_shape",
        "observed_response_shape",
        "policy_anchors_expected",
        "policy_anchors_observed",
        "human_gate_required",
        "human_gate_observed",
        "tool_calls_requested",
        "tool_calls_approved",
        "tool_calls_blocked",
        "unauthorized_tool_action",
        "untrusted_instruction_present",
        "untrusted_instruction_type",
        "policy_anchor_confidence",
        "expert_disagreement_level",
        "review_context_required",
        "public_response_allowed",
        "private_reviewer_note_allowed",
        "must_log_route",
        "required_tool_calls",
        "required_audit_events",
        "forbidden_tool_calls",
        "failure_modes",
        "observed_failure_modes",
        "derived_audit_finding_modes",
        "derived_audit_findings",
        "scores",
        "replay_status",
        "prior_replay_records",
        "release_split",
        "public_response_constraint",
        "private_reviewer_note_content_hash",
        "expected_provenance_hash",
        "canary_signature_hash",
        "is_private_or_canary",
        "model_version",
        "router_version",
        "policy_version",
        "replay_batch_id",
        "notes_public_safe",
    }
