"""Service-exposure (Rung 4) tests: detect network-facing running services, promote
their findings, and never over-claim (upgrade-only; silent without an init system)."""

from __future__ import annotations

from pathlib import Path

from firmgraph.enrich.ranking import rank_findings
from firmgraph.enrich.service_exposure import analyze_service_exposure
from firmgraph.models import Finding


def _f(fid: str, component: str) -> Finding:
    return Finding(finding_id=fid, kind="cve", severity="high", component=component)


def _rootfs_with_services(root: Path, scripts: dict[str, str]) -> None:
    initd = root / "etc" / "init.d"
    initd.mkdir(parents=True)
    for name, body in scripts.items():
        (initd / name).write_text(body)


def test_started_network_daemons_are_flagged(tmp_path: Path) -> None:
    _rootfs_with_services(
        tmp_path / "fs",
        {
            "dropbear": "#!/bin/sh\n/usr/sbin/dropbear -p 22\n",
            "S50dnsmasq": "#!/bin/sh\ndnsmasq -C /etc/dnsmasq.conf\n",
        },
    )
    findings = [
        _f("CVE-DB", "dropbear@2019.78"),
        _f("CVE-DNS", "dnsmasq@2.80"),
        _f("CVE-SSL", "openssl@1.1.1"),  # a library, not a network daemon
    ]
    updated, note, exposed = analyze_service_exposure(tmp_path, findings)
    by = {f.finding_id: f for f in updated}
    assert by["CVE-DB"].reachable is True
    assert by["CVE-DNS"].reachable is True
    assert by["CVE-SSL"].reachable is None, "a non-daemon library is not the attack surface"
    assert exposed == frozenset({"dropbear", "dnsmasq"})
    assert "remote attack surface" in note


def test_no_init_system_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "blob").mkdir()
    (tmp_path / "blob" / "fw.bin").write_bytes(b"\x00" * 32)
    updated, note, exposed = analyze_service_exposure(tmp_path, [_f("CVE-DB", "dropbear@1")])
    assert updated[0].reachable is None
    assert exposed == frozenset()
    assert "NOT APPLICABLE" in note


def test_suppressed_finding_is_left_untouched(tmp_path: Path) -> None:
    _rootfs_with_services(tmp_path / "fs", {"dropbear": "dropbear -p 22\n"})
    f = Finding(
        finding_id="CVE-DB", kind="cve", severity="high", component="dropbear@1",
        suppressed=True, suppression_reason="config: not built",
    )
    updated, _, _ = analyze_service_exposure(tmp_path, [f])
    assert updated[0].reachable is None, "suppressed findings are not resurrected"


def test_ranking_promotes_network_exposed_over_plain_severity() -> None:
    finding = _f("CVE-DB", "dropbear@2019.78")  # high severity, reachable unknown
    # Without exposure knowledge: just a high-severity finding -> P4.
    assert rank_findings([finding])[0].priority == 4
    # Known to be a started network daemon -> promoted to the act-now tier P3.
    promoted = rank_findings([finding], network_exposed=frozenset({"dropbear"}))[0]
    assert promoted.priority == 3
    assert "network-exposed running service — remote attack surface" in promoted.priority_reason
