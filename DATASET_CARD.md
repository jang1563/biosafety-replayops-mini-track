# Dataset Card: BioSafety ReplayOps Mini-Track

## Summary

BioSafety ReplayOps Mini-Track is a synthetic dataset for deterministic
validation of safeguard-routing logic in tool-using biology-assistant traces.
It pairs each case with one expected-good fixture and one expected-failure
fixture so that false refusal, unsafe pass, route drift, prompt injection,
human-gate bypass, disclosure leakage, and provenance failures remain directly
inspectable.

This dataset is not a model leaderboard or a collection of wet-lab protocols,
real user prompts, private reviewer communications, or live model outputs.

## Release and schema

| Field | Value |
| --- | --- |
| Source release | `v0.2.0` |
| Dataset schema | `0.1.6` |
| Cases | 26 |
| Fixtures | 52 |
| Languages | English |
| License | Apache-2.0 |
| Data format | Canonical JSON and row-oriented JSONL |

Two viewer configurations are supported on Hugging Face:

- `cases`: `data/replayops_cases.jsonl`
- `fixtures`: `data/fixture_traces.jsonl`

The JSON files preserve the complete top-level schema and vocabularies. The
JSONL files contain the corresponding row records for dataset viewers and
streaming loaders.

## Composition

The case set covers 12 scenario families:

- legitimate literature triage
- false-refusal probes
- missing-context clarification
- prompt-injected retrieval
- human-gated tool actions
- benign data interpretation
- high-level method comparison
- policy-boundary ambiguity
- unsafe-pass probes
- replay drift
- reviewer-disclosure attacks
- provenance-integrity attacks

Each case declares an expected route, acceptable route set, response shape,
trusted and untrusted context summaries, policy anchors, tool and audit-event
requirements, disclosure rules, and a `release_split` value. Every included
case has `release_split: "public"` and `canary_signature: null`.

Every fixture records a synthetic message trace, observed route and response
shape, requested/approved/blocked tool calls, policy anchors, human-gate state,
failure-mode labels, and version metadata. The `model_version` value is
`fixture`; it does not identify or claim evaluation of a deployed model.

Cases 023 and 024 contain synthetic `private_reviewer_note_content` strings.
They are deliberately public fixture content used to test whether a public
response improperly discloses reviewer-only context. They are not real case
records or institutional communications.

## Provenance

The released records are author-created synthetic or public-safe abstracted
examples. `source_seed: "biosafety_case_bench"` records conceptual scenario
lineage for a subset of cases; it does not import raw private prompts or
external dataset rows. No personally identifying information, credentials,
live tool output, or operational biological procedure is included.

The release validators enforce:

- exact 26-case and 52-fixture counts
- JSON/JSONL row equivalence
- public-only release splits
- absence of active per-case canary signatures
- prohibited public path and wording checks
- credential-shaped string checks
- an explicit Hugging Face upload allowlist

## Intended use

Appropriate uses include:

- unit testing deterministic safeguard routers and audit exporters
- inspecting the interaction between legitimate-use preservation and
  fail-closed hard gates
- testing prompt-injection and untrusted-context handling on synthetic traces
- regression testing replay, disclosure, and provenance invariants
- teaching evaluation design with explicit expected-good and expected-failure
  fixtures

## Out of scope

Do not use the dataset as evidence of:

- biological capability or wet-lab usefulness
- deployed-model safety or policy compliance
- real-world biosafety risk reduction
- robustness to all jailbreaks or tool attacks
- readiness for autonomous or consequential biological actions
- population-level fairness or geographic generalization

It should not be incorporated into model-training corpora. The public
`data/CANARY` GUID supports exact-match contamination checks.

## Safety and privacy

The scenarios use bounded summaries and synthetic tool stubs. They do not
contain actionable propagation parameters, procurement instructions, pathogen
optimization, evasion guidance, or stepwise experimental protocols.

Held-out development and canary splits are not present in the public
repository or Hugging Face package. The release guard rejects `_private` and
`_canary` paths and any case whose split is not public.

## Known publication incident

A prior Hugging Face publication attempt briefly included held-out synthetic
artifacts. They were removed, history was compacted, and the affected canary
was rotated. The clean `v0.2.0` release was rebuilt from an explicit allowlist.
No held-out case or active per-case canary signature is included.

## Maintenance

Schema details are documented in [SCHEMA.md](SCHEMA.md), metric interpretation
in [EVALUATION_CARD.md](EVALUATION_CARD.md), and release boundaries in
[SAFETY_POLICY.md](SAFETY_POLICY.md) and
`release/public_release_manifest.json`.
