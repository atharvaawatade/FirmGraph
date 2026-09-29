"""[4] DETECT: CVE matching behind the VulnMatcher port.

The matcher's DB snapshot date is recorded into the manifest — same scan +
same snapshot = same findings (the reproducibility receipt at work).
"""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import VulnMatcher
from firmgraph.stages.base import Stage

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


class DetectStage(Stage):
    name = "detect"
    stub = True

    def __init__(self, matcher: VulnMatcher) -> None:
        self.matcher = matcher
        self.stub = matcher.name.startswith("stub")

    def execute(self, ctx: ScanContext) -> list[str] | None:
        if not self.matcher.available():
            return [f"{self.matcher.name} not available — no CVE matching performed"]
        findings = self.matcher.findings(ctx.sbom_path, ctx.components)
        ctx.findings = sorted(
            findings,
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.finding_id, f.component or ""),
        )
        db_built = getattr(self.matcher, "db_built", None)
        if db_built:
            ctx.db_snapshots[f"{self.matcher.name}-db"] = str(db_built)
        by_sev = {
            sev: sum(1 for f in ctx.findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low")
        }
        no_fix = sum(1 for f in ctx.findings if f.fix is None)
        return [
            f"findings={len(ctx.findings)} "
            f"(C={by_sev['critical']} H={by_sev['high']} M={by_sev['medium']} "
            f"L={by_sev['low']}, no-fix={no_fix})"
        ]

    def tool_versions(self) -> dict[str, str]:
        return {self.matcher.name: "builtin"}
