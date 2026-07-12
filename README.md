# BioSafety ReplayOps Mini-Track

[![CI](https://github.com/jang1563/biosafety-replayops-mini-track/actions/workflows/ci.yml/badge.svg)](https://github.com/jang1563/biosafety-replayops-mini-track/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-Dataset-yellow)](https://huggingface.co/datasets/jang1563/biosafety-replayops-mini-track)

BioSafety ReplayOps Mini-Track is a compact, deterministic testbed for
**safeguard-routing behavior in synthetic agent traces**. It checks whether a
tool-using biology assistant preserves legitimate scientific help while
handling ambiguity, untrusted context, prompt injection, disclosure
boundaries, provenance, and consequential actions with calibrated friction.

This is a fixture-and-scorer validation artifact. It is **not** a model
leaderboard, biological capability benchmark, wet-lab protocol collection, or
measurement of real-world risk reduction.

## Release identity

- Public source release: `v0.2.0`
- Dataset schema: `0.1.6`
- Public synthetic cases: 26
- Public fixture traces: 52 (one expected-good and one expected-failure trace
  per case)
- Deterministic hard gates: 9
- Runtime dependencies: none

The `v0.2.0` source tree is a clean public root. Historical development
packets, operator runbooks, nested release snapshots, and held-out material are
not part of this repository.

## Quickstart

Dependency-free validation:

```bash
git clone https://github.com/jang1563/biosafety-replayops-mini-track
cd biosafety-replayops-mini-track
PYTHONPATH=src python3 scripts/run_replayops_selfcheck.py
```

Expected terminal marker:

```text
REPLAYOPS_SELFCHECK_OK
```

Development checks with [uv](https://docs.astral.sh/uv/):

```bash
uv sync --dev
uv run ruff check .
uv run pytest -q
uv run python scripts/check_public_manifest.py
uv run python scripts/check_public_history.py
```

## What is evaluated

The route vocabulary is `allow`, `caveat`, `clarify`, `escalate`, and
`refuse`. The scorer evaluates route and response-shape agreement alongside
legitimate-use preservation, unsafe-pass detection, trust boundaries, tool
authorization, human gates, replay integrity, disclosure boundaries, and
provenance integrity.

The nine fail-closed hard gates are:

1. `legitimate_use_gate`
2. `trust_boundary_gate`
3. `replay_integrity_gate`
4. `tool_authorization_gate`
5. `human_gate_gate`
6. `public_safe_export_gate`
7. `replay_consistency_gate`
8. `disclosure_boundary_gate`
9. `provenance_integrity_gate`

Aggregate scores are secondary. A trace that fails any hard gate must remain
inspectable as a failure even if other metrics are high.

## Repository map

| Path | Purpose |
| --- | --- |
| `data/` | Canonical JSON, viewer-friendly JSONL, metadata, and the public training-corpus canary |
| `src/biosafety_replayops/` | Schema validation, deterministic scoring, replay export, reporting, and contamination checks |
| `scripts/run_replayops_selfcheck.py` | Dependency-free end-to-end invariant check |
| `scripts/release_build.py` | Public-split and forbidden-string release guard |
| `scripts/build_hf_release.py` | Deterministic Hugging Face staging builder |
| `tests/` | Unit, schema, scope, release-boundary, and documentation tests |
| `release/public_release_manifest.json` | Machine-readable public boundary and release identity |
| `DATASET_CARD.md` | Data composition, intended use, and provenance |
| `EVALUATION_CARD.md` | Evaluation contract and metric interpretation |
| `SAFETY_POLICY.md` | Scope and publication red lines |
| `LIMITATIONS.md` | Known limitations and non-claims |
| `SCHEMA.md` | Field-level schema reference |

Generated reports are intentionally untracked. Regenerate them with:

```bash
PYTHONPATH=src python3 scripts/generate_fixture_report.py
```

## Public/private boundary

Only cases with `release_split: "public"` may be tracked or packaged. The
public corpus contains no active per-case canary signature. Paths named
`data/_private/` or `data/_canary/` are forbidden by the manifest and release
guards.

Cases 023 and 024 contain **synthetic** reviewer-note text to test disclosure
boundaries. Those strings are authored fixture content, not real institutional
records or private reviewer communications.

The Hugging Face package is built from an explicit allowlist rather than a
recursive upload:

```bash
uv run python scripts/build_hf_release.py --output .hf_release --force
uv run python scripts/validate_hf_release.py .hf_release
```

## Incident transparency

A 2026 publication attempt briefly included held-out synthetic artifacts on
Hugging Face. The files were removed, repository history was compacted, and the
affected canary was rotated. No held-out case or active per-case canary
signature is present in this public release. See [SECURITY.md](SECURITY.md) for
the current publication controls.

## Citation and license

Citation metadata is in [CITATION.cff](CITATION.cff). Code, documentation, and
the included synthetic data are released under Apache-2.0; see [LICENSE](LICENSE).
