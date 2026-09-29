"""[3] SBOM: components with provenance + confidence, behind the SbomEngine port.

Single-engine by decision (multi-engine reconciliation was cut: no ground truth).
cve-bin-tool will run alongside later, shown separately, never merged.
"""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import SbomEngine
from firmgraph.stages.base import Stage


class SbomStage(Stage):
    name = "sbom"
    stub = True

    def __init__(self, engine: SbomEngine) -> None:
        self.engine = engine
        self.stub = engine.name.startswith("stub")

    def execute(self, ctx: ScanContext) -> list[str] | None:
        if not self.engine.available():
            return [f"{self.engine.name} not available — no components cataloged"]
        root = ctx.work_dir / "extracted"
        components = self.engine.components(root)
        # Dedup by identity: overlay filesystems (e.g. OpenWrt /rom) make the same
        # package appear twice from two package-DB locations. Keep one per
        # (name, version, type). Canonical ordering after — determinism is a feature.
        seen: set[tuple[str, str, str]] = set()
        deduped = []
        for c in sorted(components, key=lambda c: (c.name, c.version or "", c.type)):
            key = (c.name, c.version or "", c.type)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        ctx.components = deduped
        syft_json = ctx.work_dir / "sbom" / "sbom.syft.json"
        if syft_json.is_file():
            ctx.sbom_path = syft_json
        db_backed = sum(1 for c in ctx.components if c.confidence >= 0.9)
        binary_only = sum(1 for c in ctx.components if c.confidence < 0.7)
        return [
            f"components={len(ctx.components)} "
            f"(package-db={db_backed}, binary-classified={binary_only})"
        ]

    def tool_versions(self) -> dict[str, str]:
        version = getattr(self.engine, "version", "builtin")
        return {self.engine.name: str(version)}
