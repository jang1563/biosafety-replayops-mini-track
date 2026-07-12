#!/usr/bin/env python3
"""Build the allowlisted Hugging Face dataset package."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "release" / "public_release_manifest.json"
SOURCE_MAP = {
    ".gitattributes": "huggingface/.gitattributes",
    "CITATION.cff": "CITATION.cff",
    "LICENSE": "LICENSE",
    "README.md": "huggingface/README.md",
    "data/CANARY": "data/CANARY",
    "data/fixture_traces.json": "data/fixture_traces.json",
    "data/fixture_traces.jsonl": "data/fixture_traces.jsonl",
    "data/fixture_traces_metadata.json": "data/fixture_traces_metadata.json",
    "data/replayops_cases.json": "data/replayops_cases.json",
    "data/replayops_cases.jsonl": "data/replayops_cases.jsonl",
    "data/replayops_cases_metadata.json": "data/replayops_cases_metadata.json",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(output: Path, force: bool = False) -> None:
    output = output.resolve()
    if output in {ROOT.resolve(), Path("/")}:
        raise ValueError(f"unsafe output path: {output}")
    if output.exists():
        if not force:
            raise FileExistsError(f"output already exists: {output}")
        shutil.rmtree(output)
    output.mkdir(parents=True)

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected_without_sums = set(manifest["huggingface_allowed_paths"]) - {"SHA256SUMS.txt"}
    if set(SOURCE_MAP) != expected_without_sums:
        raise ValueError("Hugging Face source map does not match public manifest")

    for destination, source in sorted(SOURCE_MAP.items()):
        source_path = ROOT / source
        destination_path = output / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)

    lines = [
        f"{_sha256(output / path)}  {path}"
        for path in sorted(SOURCE_MAP)
    ]
    (output / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    build(args.output, force=args.force)
    print(f"HF_RELEASE_BUILD_OK output={args.output.resolve()} files={len(SOURCE_MAP) + 1}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
