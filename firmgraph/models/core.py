"""Value objects (frozen pydantic models) shared across all stages.

Immutability is what makes content-addressing honest: a node's identity is the
hash of its canonicalized content, so the content must never mutate.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class ToolVersion(FrozenModel):
    name: str
    version: str


class StageRecord(FrozenModel):
    """Provenance record for one executed stage (manifest only, never hashed)."""

    name: str
    status: str  # "ok" | "stub" | "partial" | "failed"
    duration_ms: int
    notes: tuple[str, ...] = ()


class ExtractionSummary(FrozenModel):
    method: str
    confidence: float  # 0.0..1.0 — honest, surfaced, never hidden
    files_extracted: int
    notes: tuple[str, ...] = ()


class Component(FrozenModel):
    name: str
    version: str | None = None
    type: str = "unknown"
    provenance: str = "stub"  # which signal found it (package-db / binary / strings / stub)
    confidence: float = 0.0


class Finding(FrozenModel):
    finding_id: str  # CVE id or rule id
    kind: str  # "cve" | "secret" | "crypto" | "config"
    severity: str  # "critical" | "high" | "medium" | "low" | "unknown"
    source: str = "grype"  # which engine found it (grype / cve-bin-tool / checks) — never merged
    component: str | None = None
    summary: str = ""
    fix: str | None = None  # None => no fix available (EOL evidence — first-class finding)
    kev: bool = False
    epss: float | None = None
    reachable: bool | None = None  # None => heuristic not applicable (non-Linux image)
    priority: int = 5  # 1 (act now) .. 5 (background) — deterministic ranking tier
    priority_reason: str = ""
    suppressed: bool = False  # marked, never deleted — honesty over silence
    suppression_reason: str = ""


class ScanManifest(FrozenModel):
    """The reproducibility receipt: everything an auditor needs to re-run the scan."""

    scan_id: str
    firmgraph_version: str
    image_path: str
    image_sha256: str
    image_size: int
    image_format: str
    created_at: str  # ISO-8601 UTC; recorded, never hashed into node identity
    tool_versions: tuple[ToolVersion, ...] = ()
    db_snapshots: tuple[ToolVersion, ...] = ()  # e.g. grype-db / KEV / EPSS snapshot dates
    stages: tuple[StageRecord, ...] = ()
