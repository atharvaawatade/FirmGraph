"""Semantic diff tests: component/CVE deltas correct, DB-drift honesty enforced."""

from __future__ import annotations

import json
from pathlib import Path

from firmgraph.graph import GraphRepository, canonical_json, node_id, semantic_diff


def _save_scan(
    repo: GraphRepository,
    scan_id: str,
    components: dict[str, str],
    cves: dict[str, str],
    db_date: str,
    extra_findings: list[dict[str, str]] | None = None,
) -> None:
    repo.record_scan(scan_id, "f" * 64, "2026-07-07T00:00:00+00:00")
    nodes: list[tuple[str, str, str]] = []
    for name, version in components.items():
        content = {"name": name, "version": version, "type": "binary",
                   "provenance": "test", "confidence": 0.9}
        nodes.append((node_id("component", content), "component", canonical_json(content)))
    for fid, severity in cves.items():
        content = {"finding_id": fid, "kind": "cve", "severity": severity}
        nodes.append((node_id("finding", content), "finding", canonical_json(content)))
    for raw in extra_findings or []:
        nodes.append((node_id("finding", raw), "finding", canonical_json(raw)))
    repo.save_nodes(scan_id, nodes)
    repo.save_manifest(
        scan_id, json.dumps({"db_snapshots": [{"name": "grype-db", "version": db_date}]})
    )


def test_component_and_cve_deltas(tmp_path: Path) -> None:
    repo = GraphRepository(tmp_path / "g.db")
    try:
        _save_scan(repo, "scan-a",
                   components={"openssl": "1.0.2u", "busybox": "1.19.4"},
                   cves={"CVE-1": "high", "CVE-2": "medium"},
                   db_date="2026-07-01")
        _save_scan(repo, "scan-b",
                   components={"openssl": "3.0.1", "dnsmasq": "2.90"},
                   cves={"CVE-2": "medium", "CVE-3": "critical"},
                   db_date="2026-07-01")
        d = semantic_diff(repo, "scan-a", "scan-b")
    finally:
        repo.close()

    assert [c.name for c in d.components_added] == ["dnsmasq"]
    assert [c.name for c in d.components_removed] == ["busybox"]
    assert [(c.name, c.old_version, c.new_version) for c in d.components_changed] == [
        ("openssl", "1.0.2u", "3.0.1")
    ]
    assert d.cves_resolved == ("CVE-1",)
    assert d.cves_introduced == ("CVE-3",)
    assert d.new_critical_high == ("CVE-3",)
    assert d.db_changed is False
    assert d.caveats == (), "same DB snapshot => no caveat"
    assert not d.empty


def test_db_drift_caveat(tmp_path: Path) -> None:
    repo = GraphRepository(tmp_path / "g.db")
    try:
        _save_scan(repo, "a", {"openssl": "1.0.2u"}, {"CVE-1": "high"}, "2026-06-01")
        _save_scan(repo, "b", {"openssl": "1.0.2u"}, {"CVE-1": "high", "CVE-9": "high"},
                   "2026-07-01")
        d = semantic_diff(repo, "a", "b")
    finally:
        repo.close()
    assert d.db_changed is True
    assert d.caveats and "NOT firmware changes" in d.caveats[0], (
        "DB drift must be called out before anyone reads 'you introduced a CVE'"
    )


def test_non_cve_findings_excluded_from_cve_deltas(tmp_path: Path) -> None:
    repo = GraphRepository(tmp_path / "g.db")
    try:
        _save_scan(repo, "a", {"openssl": "1.0.2u"}, {}, "2026-07-01")
        _save_scan(repo, "b", {"openssl": "1.0.2u"}, {}, "2026-07-01",
                   extra_findings=[{"finding_id": "FG-SECRET-001@etc/x", "kind": "secret",
                                    "severity": "critical"}])
        d = semantic_diff(repo, "a", "b")
    finally:
        repo.close()
    assert d.cves_introduced == (), "checks findings are not CVE deltas"


def test_identical_scans_are_empty(tmp_path: Path) -> None:
    repo = GraphRepository(tmp_path / "g.db")
    try:
        _save_scan(repo, "a", {"openssl": "1.0.2u"}, {"CVE-1": "high"}, "2026-07-01")
        _save_scan(repo, "b", {"openssl": "1.0.2u"}, {"CVE-1": "high"}, "2026-07-01")
        d = semantic_diff(repo, "a", "b")
    finally:
        repo.close()
    assert d.empty
