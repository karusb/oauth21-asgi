"""Validate the license metadata required for distribution publication."""

from __future__ import annotations

import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
license_file = root / "LICENSE"
if (
    not license_file.is_file()
    or license_file.stat().st_size < 100
    or not isinstance(project.get("license"), str)
    or not project["license"].strip()
    or "LICENSE" not in project.get("license-files", [])
):
    raise SystemExit("Publication requires LICENSE and valid SPDX/license-files metadata")
print("Distribution license metadata validated")
