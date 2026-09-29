"""Mutable per-scan state passed through the pipeline (Pipes & Filters)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from firmgraph.models import Component, ExtractionSummary, Finding, StageRecord


@dataclass
class ScanContext:
    image_path: Path
    out_dir: Path
    work_dir: Path
    db_path: Path
    firmgraph_version: str

    scan_id: str = ""
    image_sha256: str = ""
    image_size: int = 0
    image_format: str = "unknown"

    extraction: ExtractionSummary | None = None
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    sbom_path: Path | None = None  # syft-json document, consumed by the vuln matcher
    db_snapshots: dict[str, str] = field(default_factory=dict)  # e.g. grype-db build date
    # AI explanations live OUTSIDE findings: they never enter graph nodes, so
    # LLM drift can never break the determinism guarantee. Advisory, by design.
    explanations: dict[str, str] = field(default_factory=dict)

    tool_versions: dict[str, str] = field(default_factory=dict)
    stage_log: list[StageRecord] = field(default_factory=list)
    report_paths: list[Path] = field(default_factory=list)
    node_count: int = 0

    def record_stage(self, record: StageRecord) -> None:
        self.stage_log.append(record)
