# Security and Release-Boundary Reporting

Use GitHub private vulnerability reporting for suspected credential exposure,
held-out-data leakage, release-boundary bypass, or a defect in the public-tree,
history, or Hugging Face staging guards.

Please include:

- affected release or commit;
- the path or validator involved;
- whether the content is reachable from a public ref;
- a minimal reproduction that does not paste held-out content.

Do not open a public issue containing credentials, active canary values,
unpublished cases, private reviewer material, or direct links to leaked
objects.

This repository requires no runtime secrets. Examples and CI must use
synthetic fixtures and local stubs only.

The release boundary is enforced by:

- `release/public_release_manifest.json`;
- `scripts/check_public_manifest.py`;
- `scripts/check_public_history.py`;
- `scripts/release_build.py`;
- `scripts/build_hf_release.py` and `scripts/validate_hf_release.py`.

Security-sensitive release changes should fail closed until the current tree,
full reachable history, staged Hugging Face package, tests, and self-check all
pass.
