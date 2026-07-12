# Limitations

## Fixture validation, not model evaluation

The dataset contains authored synthetic traces. It does not contain repeated
runs from a model, stochastic outputs, or deployment telemetry. Passing the
fixtures demonstrates that the bundled deterministic implementation satisfies
its test contracts; it does not prove that a model will behave safely.

## Small and deliberately structured corpus

Twenty-six cases cannot represent the full range of biological domains,
institutions, policies, user intents, languages, tool surfaces, or adaptive
attacks. The balanced 26-good/26-failure fixture design is intentional for
software validation and must not be interpreted as a prevalence estimate.

## Synthetic labels and assumptions

Expected routes, acceptable route sets, policy anchors, and failure modes are
author-defined. They encode one explicit evaluation contract rather than a
universal policy. Institutional or domain experts may reasonably choose
different routes in real contexts.

The synthetic reviewer-note fields in cases 023 and 024 are designed to test a
disclosure boundary. They are not evidence about a real review process.

## Deterministic attack coverage

Prompt-injection and provenance cases use fixed synthetic patterns. The
scorer's successful detection of those patterns does not establish robustness
against adaptive, obfuscated, multilingual, or tool-mediated attacks.

## Canary limitations

The public training-corpus canary and optional private canary checks use exact
substring matching after normalization. They do not detect paraphrases,
semantic memorization, partial leakage below the match threshold, or indirect
training influence.

## No biological capability measurement

The examples intentionally omit operational procedure detail. The artifact
cannot measure wet-lab usefulness, protocol execution, biological design
ability, pathogen knowledge, or end-to-end research capability.

## No real-world risk estimate

Hard gates are inspectable software invariants. They do not quantify accident
probability, misuse likelihood, institutional control effectiveness, or risk
reduction in deployment.

## Publication history

A prior publication attempt briefly exposed held-out synthetic artifacts. They
were removed and the affected canary was rotated. Although the current release
was rebuilt as a clean public root, users should treat the benchmark as having
a documented contamination-history event when interpreting evaluations.

## Versioning

Source release `v0.2.0` packages dataset schema `0.1.6`. A source-release bump
does not imply that case content or schema semantics changed. Consumers should
record both identities.
