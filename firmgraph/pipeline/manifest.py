"""Manifest builder: the reproducibility receipt.

Timestamps live in the manifest, never in node identity — that split is what
lets scans be reproducible while still being auditable in time.
"""

from __future__ import annotations

from datetime import datetime, timezone

from firmgraph.models import ScanManifest, ToolVersion
from firmgraph.pipeline.context import ScanContext


def build_manifest(ctx: ScanContext) -> ScanManifest:
    return ScanManifest(
        scan_id=ctx.scan_id,
        firmgraph_version=ctx.firmgraph_version,
        image_path=str(ctx.image_path),
        image_sha256=ctx.image_sha256,
        image_size=ctx.image_size,
        image_format=ctx.image_format,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        tool_versions=tuple(
            ToolVersion(name=k, version=v) for k, v in sorted(ctx.tool_versions.items())
        ),
        db_snapshots=tuple(
            ToolVersion(name=k, version=v) for k, v in sorted(ctx.db_snapshots.items())
        ),
        stages=tuple(ctx.stage_log),
    )
