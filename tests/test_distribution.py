"""Publication checks must reject inconsistent wheel and sdist metadata."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from oauth21_asgi import __version__

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def check_distributions(tmp_path, *, broken=None, target="wheel", tag=None):
    headers = {
        "Metadata-Version": "2.4",
        "Name": PROJECT["name"],
        "Version": __version__,
        "License-Expression": PROJECT["license"],
        "License-File": "LICENSE",
        "Requires-Python": PROJECT["requires-python"],
        "Description-Content-Type": "text/markdown",
    }
    metadata = "\n".join(f"{key}: {value}" for key, value in headers.items())
    metadata += "\n" + "\n".join(
        f"Project-URL: {label}, {url}" for label, url in PROJECT["urls"].items()
    )
    metadata += "\n\n" + (ROOT / "README.md").read_text(encoding="utf-8")
    changed = metadata
    if broken:
        key, expected, replacement = broken
        changed = changed.replace(f"{key}: {expected}", f"{key}: {replacement}", 1)
    wheel_metadata = changed if target == "wheel" else metadata
    sdist_metadata = changed if target == "sdist" else metadata
    with zipfile.ZipFile(tmp_path / "package.whl", "w") as wheel:
        wheel.writestr("package.dist-info/METADATA", wheel_metadata)
        wheel.writestr("package.dist-info/licenses/LICENSE", "license")
        wheel.writestr("oauth21_asgi/py.typed", "")
    with tarfile.open(tmp_path / "package.tar.gz", "w:gz") as archive:
        for name, content in {
            "PKG-INFO": sdist_metadata,
            "LICENSE": "license",
            "src/oauth21_asgi/server.py": "",
            "src/oauth21_asgi/py.typed": "",
            "examples/fastapi_app.py": "",
        }.items():
            data = content.encode("utf-8")
            entry = tarfile.TarInfo(f"package/{name}")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    env = {key: value for key, value in os.environ.items() if key != "RELEASE_TAG"}
    if tag:
        env["RELEASE_TAG"] = tag
    return subprocess.run(  # noqa: S603 -- fixed interpreter and repository script, no shell
        [sys.executable, str(ROOT / "scripts/check_distribution.py"), str(tmp_path)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_valid_distributions_and_release_tag(tmp_path):
    result = check_distributions(tmp_path, tag=f"v{__version__}")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("target", ["wheel", "sdist"])
@pytest.mark.parametrize(
    ("broken", "error"),
    [
        (("Version", __version__, "999.0.0"), "identity differs"),
        (("License-Expression", PROJECT["license"], "MIT"), "license expression differs"),
        (("License-File", "LICENSE", "MISSING"), "License metadata missing"),
        (("Requires-Python", PROJECT["requires-python"], ">=3.9"), "Python requirement differs"),
        (("Description-Content-Type", "text/markdown", "text/plain"), "content type missing"),
        (("Project-URL", f"Source, {PROJECT['urls']['Source']}", "Source, invalid"), "URLs differ"),
    ],
)
def test_inconsistent_metadata_is_rejected(tmp_path, target, broken, error):
    result = check_distributions(tmp_path, broken=broken, target=target)
    assert result.returncode != 0
    assert error in result.stderr


def test_mismatched_release_tag_is_rejected(tmp_path):
    result = check_distributions(tmp_path, tag="v999.0.0")
    assert result.returncode != 0
    assert "Release tag does not match" in result.stderr
