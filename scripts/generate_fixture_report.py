#!/usr/bin/env python3
"""Generate the ReplayOps fixture validation report."""

from __future__ import annotations

from pathlib import Path

from biosafety_replayops import ReplayOpsLoader
from biosafety_replayops.report import write_report


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    loader = ReplayOpsLoader.from_root(root)
    loader.validate_or_raise()
    write_report(loader.cases(), loader.fixtures(), root / "results")


if __name__ == "__main__":
    main()
