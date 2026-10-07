"""Require a complete, unambiguous checksum manifest before publication."""

from __future__ import annotations

import hashlib
import re
import secrets
import sys
from pathlib import Path


def verify(folder: Path) -> None:
    wheels, sdists = list(folder.glob("*.whl")), list(folder.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Exactly one wheel and one sdist are required")
    expected = {path.name: path for path in (*wheels, *sdists)}
    manifest = folder / "SHA256SUMS"
    if {path.name for path in folder.iterdir()} != {*expected, manifest.name}:
        raise SystemExit("Unexpected or missing release files")
    if any(path.is_symlink() or not path.is_file() for path in (*expected.values(), manifest)):
        raise SystemExit("Release files must be regular files")
    if manifest.stat().st_size > 16_384:
        raise SystemExit("Checksum manifest too large")
    try:
        lines = manifest.read_text(encoding="ascii").splitlines()
    except UnicodeError as error:
        raise SystemExit("Invalid checksum manifest encoding") from error
    hashes: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        if not match:
            raise SystemExit("Invalid checksum manifest entry")
        checksum, name = match.groups()
        if name not in expected or name in hashes:
            raise SystemExit("Unknown or duplicate checksum entry")
        hashes[name] = checksum.lower()
    if hashes.keys() != expected.keys():
        raise SystemExit("Manifest must cover every distribution exactly once")
    for name, path in expected.items():
        with path.open("rb") as artifact:
            actual = hashlib.file_digest(artifact, "sha256").hexdigest()
        if not secrets.compare_digest(actual, hashes[name]):
            raise SystemExit("Release artifact checksum mismatch")
    print("Verified complete wheel/sdist checksum manifest")


if __name__ == "__main__":
    verify(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
