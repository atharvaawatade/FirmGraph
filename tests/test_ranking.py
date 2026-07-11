"""Ranking policy tests: KEV > EPSS > reachable+severe > severe > rest, deterministic."""

from __future__ import annotations

from firmgraph.enrich.ranking import rank_findings
from firmgraph.models import Finding


def _f(fid: str, **kw: object) -> Finding:
    base: dict[str, object] = {"finding_id": fid, "kind": "cve", "severity": "medium"}
    base.update(kw)
    return Finding.model_validate(base)


FINDINGS = [
    _f("CVE-LOW", severity="low"),
    _f("CVE-CRIT", severity="critical"),
    _f("CVE-REACH", severity="high", reachable=True),
    _f("CVE-EPSS", severity="medium", epss=0.42),
    _f("CVE-KEV", severity="low", kev=True),
    _f("CVE-SUPP", severity="critical", kev=True, suppressed=True, suppression_reason="fp"),
]


def test_tier_order() -> None:
    ranked = rank_findings(FINDINGS)
    order = [f.finding_id for f in ranked]
    assert order[:5] == ["CVE-KEV", "CVE-EPSS", "CVE-REACH", "CVE-CRIT", "CVE-LOW"]
    assert order[-1] == "CVE-SUPP", "suppressed sinks to the bottom, never vanishes"


def test_priorities_and_reasons_assigned() -> None:
    ranked = {f.finding_id: f for f in rank_findings(FINDINGS)}
    assert ranked["CVE-KEV"].priority == 1 and "KEV" in ranked["CVE-KEV"].priority_reason
    assert ranked["CVE-EPSS"].priority == 2 and "EPSS" in ranked["CVE-EPSS"].priority_reason
    assert ranked["CVE-REACH"].priority == 3 and "reachable" in ranked["CVE-REACH"].priority_reason
    assert ranked["CVE-CRIT"].priority == 4
    assert ranked["CVE-LOW"].priority == 5


def test_ranking_is_deterministic() -> None:
    a = [f.finding_id for f in rank_findings(FINDINGS)]
    b = [f.finding_id for f in rank_findings(list(reversed(FINDINGS)))]
    assert a == b, "same inputs in any order must produce the same ranking"
