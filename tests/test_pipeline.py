"""End-to-end walking-skeleton test: scan -> manifest + reports + exports exist,
stubs are honestly labeled, and the liability line is on every artifact."""

from __future__ import annotations

import json
import random
from pathlib import Path

from firmgraph.adapters import StubExtractor, StubSbomEngine, StubVulnMatcher
from firmgraph.report.renderer import LIABILITY_LINE
from firmgraph.scanner import Scanner


def _demo_image(path: Path) -> Path:
    rng = random.Random(7)
    path.write_bytes(b"hsqs" + bytes(rng.getrandbits(8) for _ in range(4096)))
    return path


def test_scan_end_to_end(tmp_path: Path) -> None:
    image = _demo_image(tmp_path / "demo.bin")
    out = tmp_path / "out"
    result = Scanner(db_path=tmp_path / "graph.db", extractor=StubExtractor(), sbom_engine=StubSbomEngine(), matcher=StubVulnMatcher()).scan(image, out_dir=out, quiet=True)

    m = result.manifest
    assert m.image_sha256 and m.image_size > 0
    assert m.image_format == "squashfs"  # magic sniffing works
    assert m.scan_id.startswith(m.image_sha256[:12])

    stage_names = [s.name for s in m.stages]
    assert stage_names == [
        "ingest", "extract", "sbom", "detect", "binscan", "checks", "enrich", "explain", "graph", "report", "export",
    ]
    # stubs must say so — no silent placeholder data (the Dahua lesson)
    assert {s.name for s in m.stages if s.status == "stub"} >= {"extract", "sbom", "detect"}  # stub extractor injected
    assert not [s for s in m.stages if s.status == "failed"]

    html = (out / "report.html").read_text(encoding="utf-8")
    md = (out / "report.md").read_text(encoding="utf-8")
    assert LIABILITY_LINE in html and LIABILITY_LINE in md
    assert "Walking-skeleton" in html  # stub banner rendered

    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert graph["scan_id"] == m.scan_id
    assert result.node_count == len(graph["node_ids"]) > 0
