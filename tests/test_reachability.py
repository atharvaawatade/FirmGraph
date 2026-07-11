"""Reachability heuristic tests: Linux rootfs detection, honest N/A on non-Linux."""

from __future__ import annotations

from pathlib import Path

from firmgraph.enrich.reachability import analyze_reachability
from firmgraph.models import Finding


def _f(fid: str, component: str) -> Finding:
    return Finding(finding_id=fid, kind="cve", severity="high", component=component)


def _linux_rootfs(root: Path) -> None:
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "etc" / "init.d" / "S50services").write_text("#!/bin/sh\ndnsmasq --conf /etc/x\n")
    (root / "bin").mkdir()
    (root / "bin" / "busybox").write_bytes(b"\x7fELF")
    (root / "lib").mkdir()
    (root / "lib" / "libssl.so.1.0.0").write_bytes(b"\x7fELF")


def test_linux_rootfs_reachability(tmp_path: Path) -> None:
    _linux_rootfs(tmp_path / "fs")
    findings = [
        _f("CVE-1", "busybox@1.19.4"),   # binary in PATH dir
        _f("CVE-2", "openssl@1.0.2u"),   # lib alias (libssl)
        _f("CVE-3", "dnsmasq@2.80"),     # referenced by init script
        _f("CVE-4", "ghostlib@9.9"),     # nowhere -> not reachable
    ]
    updated, note = analyze_reachability(tmp_path, findings)
    by_id = {f.finding_id: f for f in updated}
    assert by_id["CVE-1"].reachable is True
    assert by_id["CVE-2"].reachable is True
    assert by_id["CVE-3"].reachable is True
    assert by_id["CVE-4"].reachable is False
    assert "Linux-filesystem heuristic" in note
    assert "misses dlopen" in note, "the limitation must be stated, not hidden"


def test_non_linux_image_is_honestly_na(tmp_path: Path) -> None:
    blob = tmp_path / "rtos"
    blob.mkdir()
    (blob / "firmware.blob").write_bytes(b"\x00" * 128)
    findings = [_f("CVE-1", "freertos@10.0")]
    updated, note = analyze_reachability(tmp_path, findings)
    assert updated[0].reachable is None, "no Linux markers => heuristic stays silent"
    assert "NOT APPLICABLE" in note
