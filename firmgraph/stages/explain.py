"""[5b] EXPLAIN: AI explanations for the top-priority findings (advisory, optional).

Runs AFTER enrich (needs priorities) and BEFORE graph/report. It only reads
findings and writes to ctx.explanations — never mutates findings, so graph
determinism is untouchable by design, not by discipline.
"""

from __future__ import annotations

from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import Explainer
from firmgraph.stages.base import Stage

_MAX_EXPLAINED = 10  # top findings only: cost- and attention-bounded


class ExplainStage(Stage):
    name = "explain"

    def __init__(self, explainer: Explainer) -> None:
        self.explainer = explainer
        self.off = explainer.name.startswith("null")

    def execute(self, ctx: ScanContext) -> list[str] | None:
        if self.off:
            return ["AI explainer: off (no key / not installed) — tool fully functional without it"]
        top = [f for f in ctx.findings if not f.suppressed and f.priority <= 3][:_MAX_EXPLAINED]
        if not top:
            return ["no priority findings to explain"]
        explained = 0
        for finding in top:
            text = self.explainer.explain(finding)
            if text:
                ctx.explanations[finding.finding_id] = text
                explained += 1
        return [
            f"AI explanations: {explained}/{len(top)} top findings "
            f"(engine={self.explainer.name}, advisory, cached)"
        ]

    def tool_versions(self) -> dict[str, str]:
        model = getattr(self.explainer, "model", None)
        if model:
            from firmgraph.triage.explainer import PROMPT_VERSION

            return {"explainer": f"{model}@{PROMPT_VERSION}"}
        return {}
