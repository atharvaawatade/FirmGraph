"""Binwalk fallback adapter.

Phase 0 lesson recorded: host binwalk broke on the happy path (missing
sasquatch). So binwalk is the *fallback*, its confidence is capped, and a
missing external extractor is reported as a note, never hidden.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from firmgraph.models import ExtractionSummary
from firmgraph.security.jail import sweep_jail

DEFAULT_TIMEOUT_S = 900
_FALLBACK_CAP = 0.5  # binwalk gives no coverage ratio; never claim more than this


class BinwalkAdapter:
    name = "binwalk"

    def __init__(self, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s

    def available(self) -> bool:
        return shutil.which("binwalk") is not None

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        dest.mkdir(parents=True, exist_ok=True)
        notes: list[str] = ["fallback engine: confidence capped, no coverage ratio available"]
        try:
            proc = subprocess.run(
                ["binwalk", "-e", "-M", str(image), "-C", str(dest)],
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
            )
            failures = [
                line.strip()
                for line in (proc.stdout + proc.stderr).splitlines()
                if "Failed to" in line or "failed!" in line
            ]
            for failure in sorted(set(failures))[:5]:
                notes.append(f"binwalk: {failure}")
        except subprocess.TimeoutExpired:
            notes.append(f"TIMEOUT after {self.timeout_s}s — partial extraction")

        jail = sweep_jail(dest)
        confidence = _FALLBACK_CAP if jail.files > 0 else 0.0
        return ExtractionSummary(
            method=self.name,
            confidence=confidence,
            files_extracted=jail.files,
            notes=(*notes, *jail.violations),
        )
