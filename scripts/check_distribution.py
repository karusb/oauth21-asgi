"""Validate the actual wheel/sdist and single authoritative version; no upload."""

from __future__ import annotations

import ast
import email
import os
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
source = ast.parse((root / "src/oauth21_asgi/_version.py").read_text())
version = next(ast.literal_eval(n.value) for n in source.body if isinstance(n, ast.Assign))
if "version" in project or "version" not in project.get("dynamic", []):
    raise SystemExit("Version must be dynamic and come only from _version.py")
if os.environ.get("RELEASE_TAG") and os.environ["RELEASE_TAG"] != "v" + version:
    raise SystemExit("Release tag does not match package version")
folder = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
wheels, sdists = list(folder.glob("*.whl")), list(folder.glob("*.tar.gz"))
if len(wheels) != 1 or len(sdists) != 1:
    raise SystemExit("Exactly one wheel and one sdist are required")
with zipfile.ZipFile(wheels[0]) as wheel:
    names = wheel.namelist()
    metadata = email.message_from_bytes(
        wheel.read(next(n for n in names if n.endswith("/METADATA")))
    )
    if metadata["Name"] != project["name"] or metadata["Version"] != version:
        raise SystemExit("Built distribution identity differs from source")
    if metadata["License-Expression"] != project["license"]:
        raise SystemExit("Built license expression differs from source")
    if "LICENSE" not in metadata.get_all("License-File", []):
        raise SystemExit("License metadata missing")
    if not any(n.endswith(".dist-info/licenses/LICENSE") for n in names):
        raise SystemExit("Wheel license file missing")
    if "oauth21_asgi/py.typed" not in names:
        raise SystemExit("Typed marker missing")
with tarfile.open(sdists[0]) as archive:
    names = archive.getnames()
    # Inspect names only; NEVER extract untrusted archives here.
    if not any(n.endswith("/LICENSE") for n in names):
        raise SystemExit("sdist license missing")
    if not any(n.endswith("/src/oauth21_asgi/server.py") for n in names):
        raise SystemExit("sdist source missing")
    if not any(n.endswith("/examples/fastapi_app.py") for n in names):
        raise SystemExit("sdist example missing")
print(f"Validated {project['name']} {version}: wheel and sdist")
