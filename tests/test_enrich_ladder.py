"""Integration: the reachability ladder composes correctly through EnrichStage.

Unit tests prove each analyzer in isolation; this proves they compose in the REAL stage —
the order, the override semantics (linkage beats the presence heuristic), the exposed-set
threaded into ranking, and kernel-config suppression — on a crafted-but-realistic rootfs
with genuine ELF binaries. This is exactly the wiring a real-firmware run depends on.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from firmgraph.models import Finding
from firmgraph.pipeline.context import ScanContext
from firmgraph.stages.enrich import EnrichStage

ElfFactory = Callable[[str, list[str]], bytes]


def _kernel_config(path: Path) -> None:
    lines = ["CONFIG_WLAN=y", "CONFIG_EXT4_FS=y", "# CONFIG_BT is not set", "# CONFIG_DRM is not set"]
    lines += [f"# CONFIG_PAD_{i} is not set" for i in range(60)]  # >=50 unset => "complete"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def _build_rootfs(extracted: Path, minimal_elf: ElfFactory) -> None:
    _kernel_config(extracted / "boot" / "config-5.4.0")  # BT + DRM compiled OUT
    # an executable that dynamically links libssl -> libssl enters the load closure
    (extracted / "bin").mkdir(parents=True)
    (extracted / "bin" / "httpd").write_bytes(minimal_elf("httpd", ["libssl.so.1.1"]))
    # libssl: linked (reachable). libfoo: present but linked by NOTHING (downgrade).
    (extracted / "usr" / "lib").mkdir(parents=True)
    (extracted / "usr" / "lib" / "libssl.so.1.1").write_bytes(minimal_elf("libssl.so.1.1", []))
    (extracted / "usr" / "lib" / "libfoo.so.1").write_bytes(minimal_elf("libfoo.so.1", []))
    # init starts dropbear -> the remote attack surface
    initd = extracted / "etc" / "init.d"
    initd.mkdir(parents=True)
    (initd / "dropbear").write_text("#!/bin/sh\n/usr/sbin/dropbear -p 22\n")


def test_reachability_ladder_composes(tmp_path: Path, minimal_elf: ElfFactory) -> None:
    extracted = tmp_path / "extracted"
    _build_rootfs(extracted, minimal_elf)

    findings = [
        Finding(finding_id="CVE-BT", kind="cve", severity="high", component="linux@5.4.0",
                summary="In the Linux kernel, net/bluetooth/l2cap use-after-free"),
        Finding(finding_id="CVE-DRM", kind="cve", severity="high", component="linux@5.4.0",
                summary="drivers/gpu/drm/i915 out-of-bounds"),
        Finding(finding_id="CVE-NET", kind="cve", severity="high", component="linux@5.4.0",
                summary="net/ipv4/tcp remote crash"),
        Finding(finding_id="CVE-SSL", kind="cve", severity="critical", component="openssl@1.1.1",
                summary="SSL flaw"),
        Finding(finding_id="CVE-FOO", kind="cve", severity="high", component="foo@1.0",
                summary="foo lib flaw"),
        Finding(finding_id="CVE-DROP", kind="cve", severity="critical", component="dropbear@2019.78",
                summary="dropbear auth bypass"),
    ]

    ctx = ScanContext(
        image_path=tmp_path / "fw.img", out_dir=tmp_path / "out", work_dir=tmp_path,
        db_path=tmp_path / "db", firmgraph_version="0.1.0",
    )
    ctx.findings = findings
    EnrichStage(suppressions_path=tmp_path / "none.yaml").execute(ctx)
    by = {f.finding_id: f for f in ctx.findings}

    # Rung 1 — kernel-config suppression (with proof); core-net has no signal, survives.
    assert by["CVE-BT"].suppressed and "CONFIG_BT" in by["CVE-BT"].suppression_reason
    assert by["CVE-DRM"].suppressed
    assert not by["CVE-NET"].suppressed, "core-net CVE has no subsystem signal -> kept"

    # Rung 2 — ELF linkage OVERRIDES the optimistic presence heuristic:
    #   libssl is actually linked (confirmed), libfoo is present-but-unlinked (downgraded).
    assert by["CVE-SSL"].reachable is True
    assert by["CVE-FOO"].reachable is False

    # Rung 4 — service exposure promotes the started network daemon to the act-now tier.
    assert by["CVE-DROP"].reachable is True
    assert by["CVE-DROP"].priority == 3
    assert "network-exposed running service" in by["CVE-DROP"].priority_reason
