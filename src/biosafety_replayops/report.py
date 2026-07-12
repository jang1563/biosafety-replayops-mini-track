"""Report generation for ReplayOps fixture validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .replay_export import export_replay_record
from .scorer import GATE_METRICS, score_fixtures, summarize_scores

GATE_LABELS = {
    "legitimate_use_gate": "Legitimate use",
    "trust_boundary_gate": "Trust boundary",
    "replay_integrity_gate": "Replay integrity",
    "tool_authorization_gate": "Tool authorization",
    "human_gate_gate": "Human gate",
    "public_safe_export_gate": "Public-safe export",
    "replay_consistency_gate": "Replay consistency",
    "disclosure_boundary_gate": "Disclosure boundary",
    "provenance_integrity_gate": "Provenance integrity",
}


def build_report(
    cases: dict[str, dict[str, Any]],
    fixtures: list[dict[str, Any]],
    held_out_aggregates: list[dict[str, Any]] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return markdown and JSON-ready report payload.

    ``held_out_aggregates`` is an optional list of aggregate dicts for
    held-out splits (private/canary). Each entry must contain
    ``split_name`` (str), ``case_count`` (int), ``fixture_count`` (int),
    ``hard_gate_pass_count`` (int), ``hard_gate_fail_count`` (int),
    and (for canary) ``contamination_alerts`` (int). No per-case detail
    is emitted; this preserves the AILuminate-style aggregate-only
    public reporting contract.
    """

    rows = score_fixtures(cases, fixtures)
    summary = summarize_scores(rows)
    fixtures_by_id = {fixture["fixture_id"]: fixture for fixture in fixtures}
    replay_records = [
        export_replay_record(
            cases[row["case_id"]],
            fixtures_by_id[row["fixture_id"]],
            row["scores"],
            row["derived_audit_findings"],
        )
        for row in rows
    ]

    payload = {
        "dataset_name": "BioSafety ReplayOps Mini-Track",
        "report_type": "Fixture And Gate Validation Report",
        "summary": summary,
        "rows": rows,
        "replay_records": replay_records,
        "held_out_aggregates": held_out_aggregates or [],
        "limitations": [
            "This is an audit-first fixture validation report, not a model leaderboard.",
            "Cases are synthetic and public-safe.",
            "Scores validate route, trust-boundary, tool-gate, and replay behavior; they do not measure biological capability.",
        ],
    }

    markdown = _render_markdown(payload)
    return markdown, payload


def build_held_out_aggregate(
    cases: dict[str, dict[str, Any]],
    fixtures: list[dict[str, Any]],
    split_name: str,
    contamination_alerts: int = 0,
) -> dict[str, Any]:
    """Build an aggregate-only summary for a held-out split.

    Returns: ``{split_name, case_count, fixture_count, hard_gate_pass_count,
    hard_gate_fail_count, contamination_alerts}``. No per-case detail and
    no canary signature content is included. Mirrors AILuminate v1.1's
    private-prompts aggregate-only reporting.
    """

    rows = score_fixtures(cases, fixtures)
    pass_count = sum(1 for row in rows if row["scores"]["hard_gate_pass"] == 1.0)
    fail_count = len(rows) - pass_count
    return {
        "split_name": split_name,
        "case_count": len(cases),
        "fixture_count": len(rows),
        "hard_gate_pass_count": pass_count,
        "hard_gate_fail_count": fail_count,
        "contamination_alerts": contamination_alerts,
    }


def write_report(
    cases: dict[str, dict[str, Any]], fixtures: list[dict[str, Any]], results_dir: Path
) -> None:
    """Write markdown and JSON reports."""

    results_dir.mkdir(parents=True, exist_ok=True)
    markdown, payload = build_report(cases, fixtures)
    (results_dir / "replayops_fixture_report.md").write_text(markdown)
    (results_dir / "replayops_fixture_report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    )


def _render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# BioSafety ReplayOps Mini-Track: Fixture And Gate Validation Report",
        "",
        f"This report validates the public-safe ReplayOps fixture bundle with audit gates first ({summary['fixture_count']} fixtures across {len(summary['scenario_family_counts'])} scenario families).",
        "It is not a model leaderboard and does not measure biological capability.",
        "",
        "## Summary",
        "",
        f"- Fixture count: `{summary['fixture_count']}`",
        f"- Hard gate counts: `{summary['hard_gate_counts']}`",
        f"- Mean aggregate by fixture type: `{summary['mean_aggregate_by_fixture_type']}`",
        f"- Route counts: `{summary['route_counts']}`",
        f"- Annotated failure mode counts: `{summary['failure_mode_counts']}`",
        f"- Derived audit finding counts: `{summary['derived_audit_finding_counts']}`",
        f"- Scenario family counts: `{summary['scenario_family_counts']}`",
        "",
        "## Audit Gate Summary",
        "",
        "| Gate | Pass | Fail |",
        "| --- | ---: | ---: |",
    ]
    for gate in GATE_METRICS:
        counts = summary["gate_counts"].get(gate, {})
        lines.append(
            "| {gate} | {passed} | {failed} |".format(
                gate=GATE_LABELS[gate],
                passed=counts.get("pass", 0),
                failed=counts.get("fail", 0),
            )
        )
    lines.extend(
        [
            "",
            "## Fixture Gate Ledger",
            "",
            "| Fixture | Type | Family | Legit use | Trust | Replay | Tool auth | Human gate | Export | Consistency | Disclosure | Provenance | Status |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in payload["rows"]:
        scores = row["scores"]
        lines.append(
            "| {fixture_id} | {fixture_type} | {scenario_family} | {legit} | {trust} | "
            "{replay} | {tool} | {human} | {export} | {consistency} | {disclosure} | {provenance} | {status} |".format(
                fixture_id=row["fixture_id"],
                fixture_type=row["fixture_type"],
                scenario_family=row["scenario_family"],
                legit=_status(scores["legitimate_use_gate"]),
                trust=_status(scores["trust_boundary_gate"]),
                replay=_status(scores["replay_integrity_gate"]),
                tool=_status(scores["tool_authorization_gate"]),
                human=_status(scores["human_gate_gate"]),
                export=_status(scores["public_safe_export_gate"]),
                consistency=_status(scores["replay_consistency_gate"]),
                disclosure=_status(scores["disclosure_boundary_gate"]),
                provenance=_status(scores["provenance_integrity_gate"]),
                status=_status(scores["hard_gate_pass"]),
            )
        )
    lines.extend(
        [
            "",
            "## Metric Rows",
            "",
            "| Fixture | Expected route | Observed route | Expected match | Acceptable match | Attack-resilient match | Aggregate | Annotated failures | Derived audit findings |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for row in payload["rows"]:
        lines.append(
            "| {fixture_id} | {expected_route} | {observed_route} | "
            "{expected_route_match:.4f} | {acceptable_route_match:.4f} | "
            "{attack_resilient_route_match:.4f} | {aggregate:.4f} | "
            "{failure_modes} | {observed_failure_modes} |".format(
                fixture_id=row["fixture_id"],
                expected_route=row["expected_route"],
                observed_route=row["observed_route"],
                expected_route_match=row["scores"]["expected_route_match"],
                acceptable_route_match=row["scores"]["acceptable_route_match"],
                attack_resilient_route_match=row["scores"]["attack_resilient_route_match"],
                aggregate=row["scores"]["aggregate"],
                failure_modes=", ".join(row["failure_modes"]),
                observed_failure_modes=", ".join(row["observed_failure_modes"]) or "none",
            )
        )
    lines.extend(
        [
            "",
            "## Derived Audit Finding Evidence",
            "",
            "| Fixture | Finding | Gate | Field | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    finding_rows = [
        (row["fixture_id"], finding)
        for row in payload["rows"]
        for finding in row["derived_audit_findings"]
    ]
    if finding_rows:
        for fixture_id, finding in finding_rows:
            lines.append(
                "| {fixture_id} | {failure_mode} | {gate} | {field} | {evidence} |".format(
                    fixture_id=fixture_id,
                    failure_mode=finding["failure_mode"],
                    gate=finding["primary_gate"],
                    field=finding["field"],
                    evidence=_format_finding_evidence(finding),
                )
            )
    else:
        lines.append("| none | none | none | none | none |")
    lines.extend(
        [
            "",
            "## Metrics",
            "",
            "The report separates audit gates, split route metrics, legitimate-use preservation, tool safety, and replay integrity.",
            "Annotated failures are fixture labels; derived audit findings are computed from route, response-shape, policy-anchor, tool, and replay fields.",
            "Each derived finding includes public-safe evidence and provenance in the JSON report.",
            "Aggregate is retained only as a fixture-validation convenience and should not be read as a leaderboard score.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in payload["limitations"])

    held_out = payload.get("held_out_aggregates") or []
    if held_out:
        lines.extend(
            [
                "",
                "## Held-out Split Aggregates",
                "",
                "Aggregate-only summaries for private and canary splits. No per-case detail or canary signature content is emitted in the public report. See `SAFETY_POLICY.md` for split and publication semantics.",
                "",
                "| Split | Cases | Fixtures | Hard-gate pass | Hard-gate fail | Contamination alerts |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for aggregate in held_out:
            lines.append(
                "| {split} | {cases} | {fixtures} | {passed} | {failed} | {alerts} |".format(
                    split=aggregate.get("split_name", "?"),
                    cases=aggregate.get("case_count", 0),
                    fixtures=aggregate.get("fixture_count", 0),
                    passed=aggregate.get("hard_gate_pass_count", 0),
                    failed=aggregate.get("hard_gate_fail_count", 0),
                    alerts=aggregate.get("contamination_alerts", 0),
                )
            )

    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "This mini-track provides one line of evidence about safeguard-routing behavior under synthetic public-safe agentic workflows. It does not prove deployment safety.",
            "",
        ]
    )
    return "\n".join(lines)


def _status(score: float) -> str:
    return "PASS" if score == 1.0 else "FAIL"


def _format_finding_evidence(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    parts = [finding["explanation"]]
    for key, value in sorted(evidence.items()):
        parts.append(f"{key}={_compact_value(value)}")
    return "<br>".join(parts)


def _compact_value(value: Any) -> str:
    if isinstance(value, dict):
        inner = ", ".join(f"{key}: {_compact_value(val)}" for key, val in sorted(value.items()))
        return "{" + inner + "}"
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]"
    return str(value)
