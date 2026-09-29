"""[4b] CHECKS: secrets / weak-crypto / insecure-config rules over the extracted tree.

These are the findings device makers most often miss and auditors most care
about — and they are CERTAIN observations (the key IS in the filesystem),
unlike probabilistic CVE matches. Ranking treats them accordingly.
"""

from __future__ import annotations

from pathlib import Path

from firmgraph.checks import ChecksEngine
from firmgraph.pipeline.context import ScanContext
from firmgraph.stages.base import Stage


class ChecksStage(Stage):
    name = "checks"

    def __init__(self, rulepack: Path | None = None) -> None:
        self.engine = ChecksEngine(rulepack)

    def execute(self, ctx: ScanContext) -> list[str] | None:
        extracted = ctx.work_dir / "extracted"
        if not extracted.is_dir():
            return ["no extracted filesystem — checks skipped"]
        findings = self.engine.run(extracted)
        ctx.findings.extend(findings)
        by_kind = {
            kind: sum(1 for f in findings if f.kind == kind)
            for kind in ("secret", "crypto", "config")
        }
        return [
            f"checks findings={len(findings)} "
            f"(secret={by_kind['secret']} crypto={by_kind['crypto']} config={by_kind['config']}) "
            f"— secrets redacted by default"
        ]

    def tool_versions(self) -> dict[str, str]:
        return {"rulepack": self.engine.version}
