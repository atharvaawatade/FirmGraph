"""[5] ENRICH: reachability -> suppression -> deterministic ranking.

KEV + EPSS deliberately ride in on the vulnerability DB (grype) rather than
separate feed loaders: one snapshot, one date in the manifest, one source of
truth for determinism. A second feed with a second date would reintroduce the
reconciliation problem we cut.
"""

from __future__ import annotations

from pathlib import Path

from firmgraph.enrich import analyze_reachability, rank_findings
from firmgraph.pipeline.context import ScanContext
from firmgraph.stages.base import Stage
from firmgraph.triage.suppression import SuppressionEngine, default_suppressions_path


class EnrichStage(Stage):
    name = "enrich"

    def __init__(self, suppressions_path: Path | None = None) -> None:
        self.suppressions_path = suppressions_path or default_suppressions_path()

    def execute(self, ctx: ScanContext) -> list[str] | None:
        notes: list[str] = []
        if not ctx.findings:
            return ["no findings to enrich"]

        extracted = ctx.work_dir / "extracted"
        if extracted.is_dir():
            ctx.findings, reach_note = analyze_reachability(extracted, ctx.findings)
            notes.append(reach_note)

        engine = SuppressionEngine(self.suppressions_path)
        ctx.findings, hits = engine.apply(ctx.findings)
        if hits:
            notes.append(f"suppressed={hits} (rules: {self.suppressions_path})")

        ctx.findings = rank_findings(ctx.findings)
        active = [f for f in ctx.findings if not f.suppressed]
        tiers = {p: sum(1 for f in active if f.priority == p) for p in (1, 2, 3, 4, 5)}
        notes.append(
            f"priorities: P1={tiers[1]} P2={tiers[2]} P3={tiers[3]} "
            f"P4={tiers[4]} P5={tiers[5]}"
        )
        notes.append("KEV/EPSS source: vulnerability DB snapshot (see db_snapshots)")
        return notes
