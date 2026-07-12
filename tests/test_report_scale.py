"""Report must stay readable at enterprise scale: exec summary, per-component
grouping, and a capped flat list with the full set in the evidence pack."""

from __future__ import annotations

import random
from pathlib import Path

from firmgraph.adapters import StubExtractor, StubSbomEngine
from firmgraph.models import Component, Finding
from firmgraph.report.renderer import (
    FINDINGS_TABLE_CAP,
    _group_by_component,
    _summary,
)
from firmgraph.scanner import Scanner


def _kernel_flood(n: int) -> list[Finding]:
    return [
        Finding(
            finding_id=f"CVE-2025-{i:05d}",
            kind="cve",
            severity="high" if i % 3 else "medium",
            component="linux-kernel@6.6.73",
            fix=None if i % 5 == 0 else "6.6.99",
            kev=(i < 2),
        )
        for i in range(n)
    ]


def test_summary_counts() -> None:
    findings = _kernel_flood(300) + [
        Finding(finding_id="CVE-X", kind="cve", severity="critical",
                component="openssl@1.0.2u", priority=2, kev=False)
    ]
    s = _summary(findings, component_count=2)
    assert s.findings == 301
    assert s.components == 2
    assert s.kev == 2
    assert s.critical == 1
    assert s.act_now + s.backlog == 301


def test_grouping_collapses_the_flood() -> None:
    groups = _group_by_component(_kernel_flood(2950))
    assert len(groups) == 1, "2950 kernel findings collapse to ONE component row"
    g = groups[0]
    assert g.total == 2950
    assert g.flood is True
    assert g.kev == 2


def test_grouping_orders_by_actionability() -> None:
    findings = [
        Finding(finding_id="CVE-K", kind="cve", severity="high",
                component="kernel@6", priority=4),
        Finding(finding_id="CVE-O", kind="cve", severity="high",
                component="openssl@1", priority=1, kev=True),
    ]
    groups = _group_by_component(findings)
    assert groups[0].component == "openssl@1", "most-actionable component first"


class FloodMatcher:
    name = "stub-flood"

    def available(self) -> bool:
        return True

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]:
        return _kernel_flood(250)


def test_report_caps_flat_list_but_pack_keeps_all(tmp_path: Path) -> None:
    image = tmp_path / "fw.bin"
    image.write_bytes(bytes(random.Random(1).getrandbits(8) for _ in range(1024)))
    out = tmp_path / "out"
    Scanner(
        db_path=tmp_path / "g.db",
        extractor=StubExtractor(),
        sbom_engine=StubSbomEngine(),
        matcher=FloodMatcher(),
        suppressions_path=tmp_path / "none.yaml",
    ).scan(image, out_dir=out, quiet=True)

    md = (out / "report.md").read_text(encoding="utf-8")
    assert "## Summary" in md
    assert "## Findings by component" in md
    assert f"showing {FINDINGS_TABLE_CAP} of 250" in md
    assert "150 more" in md  # 250 - 100 cap
    import json
    pack = json.loads((out / "evidence-pack" / "findings.json").read_text())
    assert len(pack) == 250, "evidence pack keeps the complete, unabridged record"
