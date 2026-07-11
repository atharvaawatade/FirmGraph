"""cve-bin-tool adapter: binary-signature scanning for the stripped executables
Syft can't name — closing the false-negative surface.

Kept strictly SEPARATE from the Grype/SBOM path (frozen decision: two engines
disagree with no ground truth, so we show both and never merge). Every finding
is tagged ``source="cve-bin-tool"`` so the report can render it in its own
section and an auditor always knows which engine spoke.

Determinism posture matches Grype: the vulnerability data feed is a pinned
snapshot; refreshing it is an explicit user action; the snapshot date rides in
the manifest. Auto-update is disabled so a scan is reproducible.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from firmgraph.models import Finding
from firmgraph.ports import BinaryScannerUnhealthy

DEFAULT_TIMEOUT_S = 1200
_SEVERITIES = {"critical", "high", "medium", "low"}

# Python-exception signatures in tool output => the tool crashed (unhealthy),
# as opposed to running cleanly and finding nothing.
_CRASH_SIGNATURES = (
    "Traceback (most recent call last)",
    "AttributeError",
    "OperationalError",  # e.g. "no such table: purl2cpe" — broken/half-built DB
    "TypeError",
    "KeyError",
    "ModuleNotFoundError",
    "no such table",
)


def _looks_like_crash(output: str) -> bool:
    """True if tool output carries a Python-exception signature (a crash), not a
    clean zero-findings run. Pure + unit-tested — the crash/clean discriminator."""
    return any(sig in output for sig in _CRASH_SIGNATURES)


# Rich draws error panels with Unicode box-drawing chars (U+2500–U+257F);
# strip the whole block so the report note is clean text, not diagram noise.
_BOX_CHARS = " " + "".join(chr(c) for c in range(0x2500, 0x2580))
_TRACEBACK_HEADER = "Traceback (most recent call last)"


def _first_error_line(output: str) -> str:
    """A concise, clean reason for the report note — the actual exception line,
    not the generic traceback header, and free of box-drawing noise."""
    for line in output.splitlines():
        stripped = line.strip(_BOX_CHARS)
        for sig in _CRASH_SIGNATURES:
            if sig == _TRACEBACK_HEADER:
                continue  # header, not the informative error
            if sig in stripped:
                return stripped[:160]
    return "tool crashed (unhealthy)"


def parse_cve_bin_tool_document(doc: list[dict[str, Any]]) -> list[Finding]:
    """Pure parser: cve-bin-tool json -> findings. Testable fully offline.

    cve-bin-tool emits a flat list of rows, one per (product, version, cve) —
    the same CVE can appear once per path, so we de-duplicate WITHIN this
    engine on (cve, component). Never across engines (frozen: no merging).
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for row in doc:
        cve_id = str(row.get("cve_number", "")).strip()
        if not cve_id or cve_id.upper() == "UNKNOWN":
            continue
        severity = str(row.get("severity", "unknown")).lower()
        if severity not in _SEVERITIES:
            severity = "unknown"
        product = str(row.get("product", "")).strip()
        version = str(row.get("version", "")).strip()
        component = f"{product}@{version}" if product else None
        key = (cve_id, component or "")
        if key in seen:
            continue
        seen.add(key)
        # cve-bin-tool marks fixed/paths differently across versions; keep it honest
        fixed = str(row.get("fixed_versions", "") or "").strip()
        fix = fixed or None
        source_file = str(row.get("paths", "") or row.get("path", "") or "").split(",")[0]
        summary = f"binary signature match in {source_file}" if source_file else "binary signature match"
        findings.append(
            Finding(
                finding_id=cve_id,
                kind="cve",
                severity=severity,
                source="cve-bin-tool",
                component=component,
                summary=summary,
                fix=fix,
            )
        )
    findings.sort(key=lambda f: (f.finding_id, f.component or ""))
    return findings


class CveBinToolAdapter:
    name = "cve-bin-tool"

    def __init__(self, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s

    def available(self) -> bool:
        return shutil.which("cve-bin-tool") is not None

    def scan(self, extracted_root: Path) -> list[Finding]:
        """Return findings, or raise BinaryScannerUnhealthy if the tool crashed.

        A missing/empty output file with a crash signature is a broken tool
        (skip cleanly); a missing/empty file with NO crash signature is a
        genuine zero-findings scan (return []). This is the crash-vs-clean line.
        """
        if not extracted_root.is_dir():
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = Path(tmp.name)
        try:
            try:
                proc = subprocess.run(
                    [
                        "cve-bin-tool",
                        "--no-0-cve-report",
                        "--offline",  # determinism + air-gapped: pinned local DB only
                        "-f", "json",
                        "-o", str(out_path),
                        str(extracted_root),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                )
            except subprocess.TimeoutExpired as exc:
                raise BinaryScannerUnhealthy(f"timeout after {self.timeout_s}s") from exc

            combined = f"{proc.stdout}\n{proc.stderr}"
            # cve-bin-tool returns the CVE count as its exit code, so a nonzero
            # exit is NOT an error — the JSON file is the source of truth.
            if out_path.is_file() and out_path.stat().st_size > 0:
                try:
                    doc = json.loads(out_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise BinaryScannerUnhealthy(f"malformed JSON output: {exc}") from exc
                return parse_cve_bin_tool_document(doc)

            # no usable output: crash (skip) vs genuine zero-findings (return [])
            if _looks_like_crash(combined):
                raise BinaryScannerUnhealthy(_first_error_line(combined))
            return []
        finally:
            out_path.unlink(missing_ok=True)
