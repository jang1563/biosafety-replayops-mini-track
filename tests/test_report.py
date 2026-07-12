"""Report generation tests."""

from __future__ import annotations

from pathlib import Path

from biosafety_replayops.report import build_report
from biosafety_replayops.schema import ReplayOpsLoader

ROOT = Path(__file__).resolve().parents[1]


def test_report_is_fixture_validation_not_leaderboard():
    loader = ReplayOpsLoader.from_root(ROOT)
    markdown, payload = build_report(loader.cases(), loader.fixtures())
    assert "Fixture And Gate Validation Report" in markdown
    assert "Audit Gate Summary" in markdown
    assert "Fixture Gate Ledger" in markdown
    assert "not a model leaderboard" in markdown
    assert payload["report_type"] == "Fixture And Gate Validation Report"


def test_report_contains_replay_records_for_all_fixtures():
    loader = ReplayOpsLoader.from_root(ROOT)
    _, payload = build_report(loader.cases(), loader.fixtures())
    assert len(payload["replay_records"]) == len(loader.fixtures())


def test_report_surfaces_hard_gate_failures_before_metric_rows():
    loader = ReplayOpsLoader.from_root(ROOT)
    markdown, payload = build_report(loader.cases(), loader.fixtures())
    assert payload["summary"]["hard_gate_counts"] == {"fail": 26, "pass": 26}
    assert "observed_failure_mode_counts" in payload["summary"]
    assert "derived_audit_finding_counts" in payload["summary"]
    assert "Derived audit findings" in markdown
    assert "Derived Audit Finding Evidence" in markdown
    assert markdown.index("## Fixture Gate Ledger") < markdown.index("## Metric Rows")
