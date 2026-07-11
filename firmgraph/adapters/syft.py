"""Syft adapter (single SBOM engine by decision — reconciliation was cut).

Every component carries provenance (which cataloger found it, via which signal)
and a confidence derived from that signal. The TP-Link lesson: 4 named packages
vs 204 executables — the user must SEE how much of the SBOM rests on binary
classification vs real package metadata.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from firmgraph.models import Component

DEFAULT_TIMEOUT_S = 600

# confidence by discovery signal — documented heuristic, not a hidden guess
_DB_CATALOGERS = ("apk", "dpkg", "rpm", "portage", "alpm", "nix")
_CONF_PACKAGE_DB = 0.9  # real package metadata
_CONF_BINARY = 0.6  # binary classifier / strings match
_CONF_DEFAULT = 0.7


def parse_syft_document(doc: dict[str, Any]) -> tuple[list[Component], str]:
    """Pure parser: syft-json -> (components, syft version). Testable offline."""
    components: list[Component] = []
    for artifact in doc.get("artifacts", []):
        name = str(artifact.get("name", "")).strip()
        if not name:
            continue
        found_by = str(artifact.get("foundBy", "unknown"))
        if any(db in found_by for db in _DB_CATALOGERS):
            confidence = _CONF_PACKAGE_DB
        elif "binary" in found_by:
            confidence = _CONF_BINARY
        else:
            confidence = _CONF_DEFAULT
        components.append(
            Component(
                name=name,
                version=str(artifact["version"]) if artifact.get("version") else None,
                type=str(artifact.get("type", "unknown")),
                provenance=found_by,
                confidence=confidence,
            )
        )
    version = str(doc.get("descriptor", {}).get("version", "unknown"))
    return components, version


class SyftAdapter:
    name = "syft"

    def __init__(self, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s
        self.version: str = "unknown"

    def available(self) -> bool:
        return shutil.which("syft") is not None

    def components(self, extracted_root: Path) -> list[Component]:
        sbom_dir = extracted_root.parent / "sbom"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        syft_json = sbom_dir / "sbom.syft.json"
        cyclonedx = sbom_dir / "sbom.cdx.json"
        spdx = sbom_dir / "sbom.spdx.json"
        proc = subprocess.run(
            [
                "syft",
                f"dir:{extracted_root}",
                "-o", f"syft-json={syft_json}",
                "-o", f"cyclonedx-json={cyclonedx}",
                "-o", f"spdx-json={spdx}",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
        )
        if proc.returncode != 0 or not syft_json.is_file():
            raise RuntimeError(f"syft failed (exit {proc.returncode}): {proc.stderr[-300:]}")
        doc = json.loads(syft_json.read_text(encoding="utf-8"))
        components, self.version = parse_syft_document(doc)
        return components
