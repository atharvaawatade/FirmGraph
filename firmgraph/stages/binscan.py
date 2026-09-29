"""[4a] BINSCAN: cve-bin-tool binary-signature scan (component depth).

Runs after DETECT (Grype/SBOM). Its findings are tagged source="cve-bin-tool"
and appended to the same findings list so they get enriched/ranked/mapped
uniformly — but the report renders them in their OWN section and we never
deduplicate across engines (frozen decision: show both, never merge).
"""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import BinaryScanner, BinaryScannerUnhealthy
from firmgraph.stages.base import Stage


class BinScanStage(Stage):
    name = "binscan"

    def __init__(self, scanner: BinaryScanner) -> None:
        self.scanner = scanner
        self.off = scanner.name.startswith("null")

    def execute(self, ctx: ScanContext) -> list[str] | None:
        if self.off or not self.scanner.available():
            return [
                "cve-bin-tool: off (not installed) — Syft+Grype still ran; "
                "tool fully functional without it"
            ]
        extracted = ctx.work_dir / "extracted"
        if not extracted.is_dir():
            return ["no extracted filesystem — binary scan skipped"]
        try:
            findings = self.scanner.scan(extracted)
        except BinaryScannerUnhealthy as exc:
            # A broken BONUS engine is a clean skip, not a scan failure — the
            # stage stays "ok" and says so honestly (no scary red row in a demo).
            return [
                f"cve-bin-tool: skipped (installed but unhealthy: {exc}) — "
                "Syft+Grype results stand; tool fully functional without it"
            ]
        ctx.findings.extend(findings)
        # (adapter de-dupes within cve-bin-tool on (cve, component); never across
        #  engines — a grype+cve-bin-tool overlap keeps both entries, each tagged)
        return [
            f"cve-bin-tool findings={len(findings)} "
            f"(binary signatures, shown separately, never merged with Grype)"
        ]

    def tool_versions(self) -> dict[str, str]:
        return {self.scanner.name: "builtin"}
