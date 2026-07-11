"""Suppression round-trip: rule saved -> applied on scan -> label captured locally."""

from __future__ import annotations

import json
from pathlib import Path

from firmgraph.models import Finding
from firmgraph.triage.suppression import SuppressionEngine


def _f(fid: str, component: str | None = None) -> Finding:
    return Finding(finding_id=fid, kind="cve", severity="high", component=component)


def test_round_trip(tmp_path: Path) -> None:
    engine = SuppressionEngine(tmp_path / "suppressions.yaml")
    engine.add_rule("CVE-2016-2148", "not compiled into our config", "busybox@1.19.4")

    findings = [_f("CVE-2016-2148", "busybox@1.19.4"), _f("CVE-2022-2068", "openssl@1.0.2u")]
    updated, hits = engine.apply(findings)

    assert hits == 1
    by_id = {f.finding_id: f for f in updated}
    assert by_id["CVE-2016-2148"].suppressed is True
    assert "not compiled" in by_id["CVE-2016-2148"].suppression_reason
    assert by_id["CVE-2022-2068"].suppressed is False


def test_component_scoping(tmp_path: Path) -> None:
    engine = SuppressionEngine(tmp_path / "s.yaml")
    engine.add_rule("CVE-X", "only for that build", "busybox@1.19.4")
    updated, hits = engine.apply([_f("CVE-X", "busybox@1.36.1")])
    assert hits == 0, "component-scoped rule must not match a different version"
    assert updated[0].suppressed is False


def test_label_captured_locally(tmp_path: Path) -> None:
    engine = SuppressionEngine(tmp_path / "s.yaml")
    engine.add_rule("CVE-Y", "test harness artifact", None)
    labels = (tmp_path / "labels.jsonl").read_text(encoding="utf-8").strip().splitlines()
    record = json.loads(labels[0])
    assert record["finding_id"] == "CVE-Y"
    assert record["label"] == "false_positive"
    assert record["reason"] == "test harness artifact"


def test_reasonless_rules_are_ignored(tmp_path: Path) -> None:
    rules = tmp_path / "s.yaml"
    rules.write_text("rules:\n  - finding_id: CVE-Z\n", encoding="utf-8")
    engine = SuppressionEngine(rules)
    assert engine.load() == [], "a suppression without a reason is a lie — rejected"
