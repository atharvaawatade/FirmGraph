"""[7] REPORT: the artifact a human shows their boss (HTML + Markdown)."""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.pipeline.manifest import build_manifest
from firmgraph.report.renderer import render_html, render_markdown
from firmgraph.stages.base import Stage


class ReportStage(Stage):
    name = "report"

    def execute(self, ctx: ScanContext) -> list[str] | None:
        ctx.out_dir.mkdir(parents=True, exist_ok=True)
        manifest = build_manifest(ctx)  # snapshot of provenance so far
        html_path = ctx.out_dir / "report.html"
        md_path = ctx.out_dir / "report.md"
        html_path.write_text(render_html(ctx, manifest), encoding="utf-8")
        md_path.write_text(render_markdown(ctx, manifest), encoding="utf-8")
        ctx.report_paths = [html_path, md_path]
        return [f"wrote {html_path.name}, {md_path.name}"]
