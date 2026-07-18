"""[5] ENRICH: reachability -> suppression -> deterministic ranking.

KEV + EPSS deliberately ride in on the vulnerability DB (grype) rather than
separate feed loaders: one snapshot, one date in the manifest, one source of
truth for determinism. A second feed with a second date would reintroduce the
reconciliation problem we cut.
"""

from __future__ import annotations

from pathlib import Path

from firmgraph.enrich import (
    analyze_elf_linkage,
    analyze_kernel_config,
    analyze_reachability,
    analyze_service_exposure,
    rank_findings,
)
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

        # Dedup by identity first: overlay filesystems can double the same match.
        # Never dedup across engines (source keeps grype/cve-bin-tool separate).
        seen: set[tuple[str, str, str, str]] = set()
        unique = []
        for f in ctx.findings:
            key = (f.finding_id, f.component or "", f.kind, f.source)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        if len(unique) != len(ctx.findings):
            notes.append(f"deduped {len(ctx.findings) - len(unique)} duplicate findings")
        ctx.findings = unique

        network_exposed: frozenset[str] = frozenset()
        extracted = ctx.work_dir / "extracted"
        if extracted.is_dir():
            ctx.findings, reach_note = analyze_reachability(extracted, ctx.findings)
            notes.append(reach_note)
            # Rung 2: refine library reachability by REAL dynamic linkage — a present
            # library that no executable loads is downgraded, with the load closure
            # as the evidence. Runs after the presence heuristic, overriding it.
            ctx.findings, elf_note = analyze_elf_linkage(extracted, ctx.findings)
            notes.append(elf_note)
            # Rung 4: the remote attack surface — network-facing services that are
            # actually started at boot. Their findings are promoted in ranking.
            ctx.findings, svc_note, network_exposed = analyze_service_exposure(
                extracted, ctx.findings
            )
            notes.append(svc_note)
            # The moat: kill the kernel version-match flood with proof from the
            # kernel's own build config, BEFORE ranking, so absent-subsystem CVEs
            # sink and flow to VEX as not_affected with the config line attached.
            ctx.findings, kcfg_note = analyze_kernel_config(extracted, ctx.findings)
            notes.append(kcfg_note)

        engine = SuppressionEngine(self.suppressions_path)
        ctx.findings, hits = engine.apply(ctx.findings)
        if hits:
            notes.append(f"suppressed={hits} (rules: {self.suppressions_path})")

        ctx.findings = rank_findings(ctx.findings, network_exposed)
        active = [f for f in ctx.findings if not f.suppressed]
        tiers = {p: sum(1 for f in active if f.priority == p) for p in (1, 2, 3, 4, 5)}
        notes.append(
            f"priorities: P1={tiers[1]} P2={tiers[2]} P3={tiers[3]} "
            f"P4={tiers[4]} P5={tiers[5]}"
        )
        notes.append("KEV/EPSS source: vulnerability DB snapshot (see db_snapshots)")
        return notes
