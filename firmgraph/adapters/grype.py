"""Grype adapter: SBOM -> CVE matches, with the DB snapshot pinned in the manifest.

Determinism posture: auto-update OFF — the same scan against the same DB
snapshot yields the same findings; refreshing the DB is an explicit user
action, and the snapshot date travels in the reproducibility receipt.

``fix=None`` is preserved deliberately: "no fix available" on an EOL component
is first-class CRA evidence (the ChirpStack lesson), not a missing value.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from firmgraph.models import Component, Finding

DEFAULT_TIMEOUT_S = 600

_SEVERITIES = {"critical", "high", "medium", "low"}


def parse_grype_document(doc: dict[str, Any]) -> tuple[list[Finding], str]:
    """Pure parser: grype-json -> (findings, db build date). Testable offline."""
    findings: list[Finding] = []
    for match in doc.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vuln_id = str(vuln.get("id", "")).strip()
        if not vuln_id:
            continue
        severity = str(vuln.get("severity", "unknown")).lower()
        if severity not in _SEVERITIES:
            severity = "unknown"
        fix_info = vuln.get("fix", {}) or {}
        fix_versions = [str(v) for v in fix_info.get("versions", []) if v]
        fix = ", ".join(sorted(set(fix_versions))) if fix_versions else None
        epss = _first_epss(vuln)
        kev = bool(vuln.get("knownExploited"))
        name = str(artifact.get("name", "")) or None
        version = str(artifact.get("version", "")) or ""
        component = f"{name}@{version}" if name else None
        findings.append(
            Finding(
                finding_id=vuln_id,
                kind="cve",
                severity=severity,
                component=component,
                summary=str(vuln.get("description", ""))[:500],
                fix=fix,
                kev=kev,
                epss=epss,
            )
        )
    # DB build date location moved in grype v6: descriptor.db.status.built.
    # Read the new path first, fall back to the old one, for the determinism
    # receipt in the scan manifest.
    db = doc.get("descriptor", {}).get("db", {}) or {}
    db_built = str(
        (db.get("status", {}) or {}).get("built")  # grype v6 schema
        or db.get("built")                          # older grype
        or "unknown"
    )
    return findings, db_built


def _first_epss(vuln: dict[str, Any]) -> float | None:
    for entry in vuln.get("epss", []) or []:
        try:
            return float(entry.get("epss"))
        except (TypeError, ValueError):
            continue
    return None


class GrypeAdapter:
    name = "grype"

    def __init__(self, timeout_s: int = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s
        self.db_built: str = "unknown"

    def available(self) -> bool:
        return shutil.which("grype") is not None

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]:
        if sbom_path is None or not sbom_path.is_file():
            return []
        env = dict(os.environ)
        env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")  # determinism: explicit refresh only
        env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        # We DELIBERATELY pin a DB snapshot (baked into the image / user-managed)
        # and record its build date in the manifest. Grype otherwise hard-refuses
        # any DB older than 5 days — which would make an air-gapped/offline scan
        # fail with no way to self-heal. Disabling the age check is what makes the
        # "works offline" promise durable rather than a 5-day fuse.
        env.setdefault("GRYPE_DB_VALIDATE_AGE", "false")
        proc = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
            env=env,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise RuntimeError(
                f"grype failed (exit {proc.returncode}): {proc.stderr[-300:]} "
                "— if the DB is missing, run: grype db update"
            )
        doc = json.loads(proc.stdout)
        findings, self.db_built = parse_grype_document(doc)
        return findings
