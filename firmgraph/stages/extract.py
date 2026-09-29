"""[2] EXTRACT: firmware -> filesystem, behind the Extractor port (Strategy).

Phase 1 wires the stub. Phase 2 registers UnblobAdapter -> BinwalkAdapter
fallback with the extraction jail — one file each, per the Modularity Contract.
"""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import Extractor
from firmgraph.stages.base import Stage


class ExtractStage(Stage):
    name = "extract"
    stub = True  # flips to False when a real extractor is registered

    def __init__(self, extractor: Extractor) -> None:
        self.extractor = extractor
        self.stub = extractor.name.startswith("stub")

    def execute(self, ctx: ScanContext) -> list[str] | None:
        dest = ctx.work_dir / "extracted"
        summary = self.extractor.extract(ctx.image_path, dest)
        ctx.extraction = summary
        return [
            f"method={summary.method} confidence={summary.confidence:.2f} "
            f"files={summary.files_extracted}"
        ]

    def tool_versions(self) -> dict[str, str]:
        return {self.extractor.name: "builtin"}
