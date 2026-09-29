"""[6] GRAPH: assemble the content-addressed Device Security Graph.

This stage IS the determinism guarantee: node identity = hash of canonical
content, edges sorted, timestamps excluded. Two scans of identical content
produce identical ids — the reproducibility acid test lives on this code.
"""

from __future__ import annotations

from firmgraph.graph.content import canonical_json, node_id
from firmgraph.graph.repository import GraphRepository
from firmgraph.pipeline.context import ScanContext
from firmgraph.stages.base import Stage


class GraphStage(Stage):
    name = "graph"

    def execute(self, ctx: ScanContext) -> list[str] | None:
        nodes: list[tuple[str, str, str]] = []
        edges: list[tuple[str, str, str]] = []

        fw_content = {
            "sha256": ctx.image_sha256,
            "size": ctx.image_size,
            "format": ctx.image_format,
        }
        fw_id = node_id("firmware", fw_content)
        nodes.append((fw_id, "firmware", canonical_json(fw_content)))

        if ctx.extraction is not None:
            ex_content = {
                "method": ctx.extraction.method,
                "confidence": ctx.extraction.confidence,
                "files_extracted": ctx.extraction.files_extracted,
                "image_sha256": ctx.image_sha256,
            }
            ex_id = node_id("extraction", ex_content)
            nodes.append((ex_id, "extraction", canonical_json(ex_content)))
            edges.append((fw_id, ex_id, "extracted_by"))

        component_ids: dict[str, str] = {}
        for comp in ctx.components:
            c_content = {
                "name": comp.name,
                "version": comp.version,
                "type": comp.type,
                "provenance": comp.provenance,
                "confidence": comp.confidence,
            }
            c_id = node_id("component", c_content)
            component_ids[comp.name] = c_id
            nodes.append((c_id, "component", canonical_json(c_content)))
            edges.append((fw_id, c_id, "contains"))

        for finding in ctx.findings:
            f_content = finding.model_dump()
            f_id = node_id("finding", f_content)
            nodes.append((f_id, "finding", canonical_json(f_content)))
            src = component_ids.get(finding.component or "", fw_id)
            edges.append((src, f_id, "affected_by"))

        # canonical ordering before persistence — determinism is a feature
        nodes.sort(key=lambda n: (n[1], n[0]))
        edges.sort()

        repo = GraphRepository(ctx.db_path)
        try:
            repo.save_nodes(ctx.scan_id, nodes)
            repo.save_edges(ctx.scan_id, edges)
        finally:
            repo.close()
        ctx.node_count = len(nodes)
        return [f"nodes={len(nodes)} edges={len(edges)}"]
