"""Unblob adapters (primary extraction engine).

Two strategies behind one port:
- ``UnblobNativeAdapter``  — unblob on PATH (inside our Docker image / Linux hosts)
- ``UnblobDockerAdapter``  — the official unblob container (macOS/dev hosts),
  run with ``--network=none``: extraction never needs the network.

Confidence = unblob's own chunk-identification ratio (parsed from its summary),
surfaced honestly. The Dahua doorbell taught us: 0.92% identified means the
report must scream, not print a green zero.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from firmgraph.models import ExtractionSummary
from firmgraph.security.jail import sweep_jail

UNBLOB_IMAGE = "ghcr.io/onekey-sec/unblob:latest"  # TODO(pin): digest-pin at V0.1.0 tag
DEFAULT_TIMEOUT_S = 900

_RATIO_RE = re.compile(r"identification ratio:\s*([0-9.]+)\s*%")


def _summary_from_output(
    method: str, dest: Path, output: str, extra_notes: tuple[str, ...] = ()
) -> ExtractionSummary:
    jail = sweep_jail(dest)
    match = _RATIO_RE.search(output)
    if match:
        confidence = min(1.0, float(match.group(1)) / 100.0)
        ratio_note = f"unblob chunk identification ratio: {match.group(1)}%"
    else:
        # honest fallback: we extracted something but can't quantify coverage
        confidence = 0.3 if jail.files > 0 else 0.0
        ratio_note = "identification ratio unavailable — conservative confidence applied"
    notes = (ratio_note, *extra_notes, *jail.violations)
    return ExtractionSummary(
        method=method,
        confidence=confidence,
        files_extracted=jail.files,
        notes=notes,
    )


class UnblobNativeAdapter:
    name = "unblob"

    def __init__(self, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s

    def available(self) -> bool:
        return shutil.which("unblob") is not None

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                ["unblob", "-e", str(dest), str(image)],
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                # unblob writes unblob.log to CWD; run from a writable dir OUTSIDE
                # the swept extraction dir so (a) a read-only working dir
                # (firmware mounted -v "$PWD:/work:ro", which we recommend) never
                # crashes extraction, and (b) the log doesn't inflate file counts.
                cwd=str(dest.parent),
            )
            output = proc.stdout + proc.stderr
            extra = () if proc.returncode == 0 else (f"unblob exit code {proc.returncode}",)
        except subprocess.TimeoutExpired:
            return _summary_from_output(
                self.name, dest, "", (f"TIMEOUT after {self.timeout_s}s — partial extraction",)
            )
        return _summary_from_output(self.name, dest, output, extra)


class UnblobDockerAdapter:
    name = "unblob-docker"

    def __init__(self, image_ref: str = UNBLOB_IMAGE, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.image_ref = image_ref
        self.timeout_s = timeout_s

    def available(self) -> bool:
        if shutil.which("docker") is None:
            return False
        probe = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=15
        )
        return probe.returncode == 0

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        dest.mkdir(parents=True, exist_ok=True)
        image = image.resolve()
        cmd = [
            "docker", "run", "--rm",
            "--network=none",  # extraction never needs the network
            "-v", f"{image}:/input/{image.name}:ro",
            "-v", f"{dest.resolve()}:/output",
            self.image_ref,
            "-e", "/output",
            f"/input/{image.name}",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s
            )
            output = proc.stdout + proc.stderr
            extra = () if proc.returncode == 0 else (f"unblob exit code {proc.returncode}",)
        except subprocess.TimeoutExpired:
            return _summary_from_output(
                self.name, dest, "", (f"TIMEOUT after {self.timeout_s}s — partial extraction",)
            )
        return _summary_from_output(self.name, dest, output, extra)
