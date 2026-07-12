# Safety Policy

## Scope

BioSafety ReplayOps Mini-Track evaluates public-safe safeguard-routing
mechanics on synthetic traces. It is designed to preserve legitimate biology
support while making ambiguity, untrusted context, tool authorization,
disclosure, provenance, and human-review boundaries explicit.

It does not evaluate biological capability and may not be represented as a
wet-lab, procurement, synthesis, or autonomous-research system.

## Content red lines

Contributions must not add:

- operational pathogen optimization
- actionable culture, propagation, or synthesis parameters
- procurement or fulfillment workflows
- evasion or detection-avoidance instructions
- raw dangerous prompts or unredacted harmful tool traces
- live external-tool execution
- autonomous consequential biological actions
- credentials, private records, or personally identifying information

Synthetic bounded summaries and inert tool stubs are required.

## Evaluation red lines

The public package performs no live model evaluation and no live browser or
tool access. It may not claim that deterministic fixture performance proves
deployed-model safety, real-world risk reduction, biological capability, or
readiness for consequential use.

Human-gate labels are evaluation concepts. They do not grant authority to act
or replace institutional review.

## Public release boundary

Only records with `release_split: "public"` may be tracked or packaged.

The following are forbidden from the public tree and Hugging Face package:

- `data/_private/`
- `data/_canary/`
- any non-public `release_split`
- any active per-case canary signature
- raw local paths, operator credentials, or infrastructure identifiers
- development handoffs, application material, and approval-state packets

The machine-readable boundary is
`release/public_release_manifest.json`. CI validates both the current tree and
every reachable Git blob.

## Training-data contamination

The public `data/CANARY` GUID marks this benchmark as evaluation data that
should not be used for training. The contamination detector uses deterministic
exact-substring matching when private canary inputs are supplied outside the
public repository. It does not claim paraphrase-robust detection.

## Incident response

A prior Hugging Face publication attempt briefly included held-out synthetic
artifacts. The files were removed, history was compacted, and the affected
canary was rotated. The current release uses an explicit file allowlist,
staging validation, JSON/JSONL equivalence checks, and a clean public history.

If a future release boundary is breached:

1. make the affected surface private or otherwise contain access;
2. identify the exact files and reachable refs;
3. rotate affected canaries or credentials;
4. rebuild from a verified allowlist;
5. disclose the material impact without publishing held-out content;
6. add a regression test before restoring public access.

## Reporting

Report suspected release-boundary, credential, or held-out-data exposure using
GitHub private vulnerability reporting. Do not paste unpublished held-out
content into a public issue.
