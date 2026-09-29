"""CRA mapping tests: deterministic rules, suppressed excluded, language discipline."""

from __future__ import annotations

from firmgraph.cra.mapping import MAPPING_DISCLAIMER, aggregate_mapping, map_finding
from firmgraph.models import Finding


def _f(fid: str, kind: str = "cve", **kw: object) -> Finding:
    base: dict[str, object] = {"finding_id": fid, "kind": kind, "severity": "high"}
    base.update(kw)
    return Finding.model_validate(base)


def test_cve_maps_to_known_vulns_and_remediation() -> None:
    refs = {r.req_id for r in map_finding(_f("CVE-1", fix="1.2.3"))}
    assert refs == {"I.2a", "II.2"}


def test_eol_cve_adds_patch_obligation() -> None:
    refs = {r.req_id for r in map_finding(_f("CVE-1", fix=None))}
    assert refs == {"I.2a", "II.2", "II.8"}, "no-fix implicates the free-patch obligation"


def test_secret_maps_to_access_and_confidentiality() -> None:
    refs = {r.req_id for r in map_finding(_f("FG-SECRET-001@etc/ssl/device.key", kind="secret"))}
    assert refs == {"I.2d", "I.2e"}


def test_config_rules_map_by_rule_id() -> None:
    telnet = {r.req_id for r in map_finding(_f("FG-CONFIG-001@etc/inittab", kind="config"))}
    ssh = {r.req_id for r in map_finding(_f("FG-CONFIG-002@etc/sshd_config", kind="config"))}
    perms = {r.req_id for r in map_finding(_f("FG-CONFIG-004@etc/config.dat", kind="config"))}
    assert telnet == {"I.2b", "I.2j"}
    assert ssh == {"I.2b", "I.2d"}
    assert perms == {"I.2f"}


def test_titles_resolved_from_annex_data() -> None:
    ref = next(r for r in map_finding(_f("CVE-1")) if r.req_id == "I.2a")
    assert "known exploitable vulnerabilities" in ref.title.lower()


def test_aggregate_excludes_suppressed_and_sorts() -> None:
    findings = [
        _f("CVE-1"),
        _f("CVE-2", suppressed=True, suppression_reason="fp"),
        _f("FG-SECRET-001@a/b/c", kind="secret"),
    ]
    rows = aggregate_mapping(findings)
    req_ids = [row.ref.req_id for row in rows]
    assert req_ids == sorted(req_ids), "deterministic order"
    all_ids = {fid for row in rows for fid in row.finding_ids}
    assert "CVE-2" not in all_ids, "suppressed findings never enter the mapping"
    assert "CVE-1" in all_ids and "FG-SECRET-001@a/b/c" in all_ids


def test_language_discipline() -> None:
    assert "not legal advice" in MAPPING_DISCLAIMER.lower()
    assert "compliant" not in MAPPING_DISCLAIMER.lower().replace("compliance determination", "")
