"""The reproducibility acid test: same image in -> identical graph node ids out.

This is the product promise as an executable test. If this test starts flaking,
the determinism guarantee is broken and nothing else matters until it's fixed.
"""

from __future__ import annotations

import random
from pathlib import Path

from firmgraph.adapters import StubExtractor, StubSbomEngine, StubVulnMatcher
from firmgraph.graph.repository import GraphRepository
from firmgraph.scanner import Scanner


def _demo_image(path: Path) -> Path:
    rng = random.Random(42)  # seeded => byte-identical demo image every time
    path.write_bytes(bytes(rng.getrandbits(8) for _ in range(65536)))
    return path


def test_two_scans_produce_identical_node_ids(tmp_path: Path) -> None:
    image = _demo_image(tmp_path / "demo.bin")

    db_a, db_b = tmp_path / "a.db", tmp_path / "b.db"
    res_a = Scanner(db_path=db_a, extractor=StubExtractor(), sbom_engine=StubSbomEngine(), matcher=StubVulnMatcher()).scan(image, out_dir=tmp_path / "out_a", quiet=True)
    res_b = Scanner(db_path=db_b, extractor=StubExtractor(), sbom_engine=StubSbomEngine(), matcher=StubVulnMatcher()).scan(image, out_dir=tmp_path / "out_b", quiet=True)

    repo_a, repo_b = GraphRepository(db_a), GraphRepository(db_b)
    try:
        nodes_a = repo_a.node_ids(res_a.manifest.scan_id)
        nodes_b = repo_b.node_ids(res_b.manifest.scan_id)
    finally:
        repo_a.close()
        repo_b.close()

    assert nodes_a, "scan produced no graph nodes"
    assert nodes_a == nodes_b, "same image must produce identical content-addressed nodes"


def test_diff_of_identical_scans_is_empty(tmp_path: Path) -> None:
    image = _demo_image(tmp_path / "demo.bin")
    db = tmp_path / "graph.db"
    scanner = Scanner(db_path=db, extractor=StubExtractor(), sbom_engine=StubSbomEngine(), matcher=StubVulnMatcher())
    r1 = scanner.scan(image, out_dir=tmp_path / "out1", quiet=True)
    r2 = scanner.scan(image, out_dir=tmp_path / "out2", quiet=True)

    repo = GraphRepository(db)
    try:
        result = repo.diff(r1.manifest.scan_id, r2.manifest.scan_id)
    finally:
        repo.close()
    assert result.empty, "identical scans must diff to empty"
