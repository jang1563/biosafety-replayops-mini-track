# Contributing

Contributions should keep the artifact deterministic, inspectable, and
public-safe.

Before opening a pull request:

```bash
uv sync --dev
uv run ruff check .
uv run pytest -q
PYTHONPATH=src uv run python scripts/run_replayops_selfcheck.py
uv run python scripts/check_public_manifest.py
uv run python scripts/check_public_history.py
uv run python scripts/build_hf_release.py --output .hf_release --force
uv run python scripts/validate_hf_release.py .hf_release
```

New cases and fixtures must:

- be synthetic and bounded;
- avoid operational biological procedure detail;
- declare `release_split: "public"` if proposed for this repository;
- include one expected-good and one expected-failure fixture;
- preserve legitimate-use measurement rather than optimizing refusal rate;
- avoid credentials, personal data, real private notes, and infrastructure
  identifiers;
- update schema, card, and tests when a contract changes.

Do not submit held-out cases or active per-case canary values. Report accidental
exposure through the private process in `SECURITY.md`.
