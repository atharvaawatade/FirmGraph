"""Kernel-config-aware suppression tests — the moat, and its honesty guards.

These tests assert the *discipline* as much as the feature: we suppress ONLY on
positive proof of absence, we stay silent when the config is missing or incomplete,
and we never touch non-kernel CVEs or core-networking CVEs that carry no subsystem
signal. Over-suppression is the failure mode that would make us liars, so it is
tested harder than the happy path.
"""

from __future__ import annotations

import gzip
from pathlib import Path

from firmgraph.enrich.kernel_config import analyze_kernel_config, extract_kernel_config
from firmgraph.models import Finding


def _kf(fid: str, summary: str, component: str = "linux@5.4.0") -> Finding:
    return Finding(
        finding_id=fid, kind="cve", severity="high", component=component, summary=summary
    )


def _write_config(
    path: Path,
    *,
    enabled: list[str],
    disabled: list[str],
    pad_unset: int = 60,
    pad_enabled: int = 0,
) -> None:
    """Write a kernel .config. pad_unset >= 50 makes it 'complete' (absence == disabled);
    pad_enabled bulks it past the min-lines sanity gate without adding 'is not set' lines."""
    lines = [f"{c}=y" for c in enabled]
    lines += [f"CONFIG_ENPAD_{i}=y" for i in range(pad_enabled)]
    lines += [f"# {c} is not set" for c in disabled]
    lines += [f"# CONFIG_PAD_{i} is not set" for i in range(pad_unset)]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def test_complete_config_suppresses_absent_subsystems_with_proof(tmp_path: Path) -> None:
    _write_config(
        tmp_path / "boot" / "config-5.4.0",
        enabled=["CONFIG_WLAN", "CONFIG_EXT4_FS"],
        disabled=["CONFIG_BT", "CONFIG_DRM", "CONFIG_XFS_FS"],
    )
    findings = [
        _kf("CVE-BT", "In the Linux kernel, net/bluetooth/l2cap use-after-free"),
        _kf("CVE-DRM", "drivers/gpu/drm/i915 out-of-bounds write"),
        _kf("CVE-XFS", "fs/xfs metadata corruption on mount"),
        _kf("CVE-WIFI", "net/mac80211 flaw"),          # CONFIG_WLAN=y -> keep
        _kf("CVE-NET", "net/ipv4/tcp remote crash"),    # no subsystem signal -> keep
        _kf("CVE-SSL", "bluetooth string in openssl", component="openssl@1.1.1"),  # not kernel
    ]
    updated, note = analyze_kernel_config(tmp_path, findings)
    by = {f.finding_id: f for f in updated}

    assert by["CVE-BT"].suppressed and by["CVE-DRM"].suppressed and by["CVE-XFS"].suppressed
    assert not by["CVE-WIFI"].suppressed, "enabled subsystem must never be suppressed"
    assert not by["CVE-NET"].suppressed, "core net CVE with no subsystem signal must survive"
    assert not by["CVE-SSL"].suppressed, "non-kernel CVE must never be touched"

    # the proof must be concrete and cite the config
    assert "Bluetooth" in by["CVE-BT"].suppression_reason
    assert "# CONFIG_BT is not set" in by["CVE-BT"].suppression_reason
    assert "config-5.4.0" in by["CVE-BT"].suppression_reason
    assert "suppressed 3/5 kernel CVEs" in note


def test_absence_from_complete_config_counts_as_disabled(tmp_path: Path) -> None:
    # NFC not listed at all, but the config is complete -> absence is proof of "off"
    _write_config(
        tmp_path / "boot" / "config-5.4.0",
        enabled=["CONFIG_WLAN"],
        disabled=["CONFIG_BT"],  # + 60 pad lines => complete
    )
    updated, _ = analyze_kernel_config(tmp_path, [_kf("CVE-NFC", "net/nfc llcp flaw")])
    assert updated[0].suppressed
    assert "absent from complete kernel config" in updated[0].suppression_reason


def test_incomplete_config_only_trusts_explicit_unset(tmp_path: Path) -> None:
    # A partial config: real-sized (passes the min-lines gate) but with too few
    # "is not set" lines to be COMPLETE. We trust "# CONFIG_BT is not set" but must
    # NOT infer that merely-absent CONFIG_NFC is disabled.
    _write_config(
        tmp_path / "etc" / ".config",
        enabled=["CONFIG_WLAN"],
        disabled=["CONFIG_BT"],
        pad_unset=4,
        pad_enabled=30,
    )
    updated, _ = analyze_kernel_config(
        tmp_path,
        [_kf("CVE-BT", "net/bluetooth flaw"), _kf("CVE-NFC", "net/nfc flaw")],
    )
    by = {f.finding_id: f for f in updated}
    assert by["CVE-BT"].suppressed, "explicit 'is not set' is trusted even in a fragment"
    assert not by["CVE-NFC"].suppressed, "incomplete config must not infer absence == disabled"


def test_no_config_is_honestly_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "rootfs").mkdir()
    (tmp_path / "rootfs" / "blob.bin").write_bytes(b"\x00" * 64)
    updated, note = analyze_kernel_config(tmp_path, [_kf("CVE-BT", "net/bluetooth flaw")])
    assert not updated[0].suppressed
    assert "NOT APPLICABLE" in note


def test_proc_config_gz_is_read(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    body = "CONFIG_WLAN=y\n# CONFIG_BT is not set\n" + "\n".join(
        f"# CONFIG_PAD_{i} is not set" for i in range(60)
    )
    with gzip.open(proc / "config.gz", "wt", encoding="utf-8") as fh:
        fh.write(body)
    cfg = extract_kernel_config(tmp_path)
    assert cfg is not None and "proc/config.gz" in cfg.source and cfg.complete
    updated, note = analyze_kernel_config(tmp_path, [_kf("CVE-BT", "net/bluetooth flaw")])
    assert updated[0].suppressed
    assert "proc/config.gz" in updated[0].suppression_reason


def test_word_boundary_keeps_short_keywords_precise(tmp_path: Path) -> None:
    # "jfs" (bare, short) must match on a word boundary, not inside another token.
    _write_config(
        tmp_path / "boot" / "config-5.4.0",
        enabled=["CONFIG_WLAN"],
        disabled=["CONFIG_JFS_FS"],
    )
    updated, _ = analyze_kernel_config(
        tmp_path, [_kf("CVE-X", "the mjfsx scheduler subsystem overflow")]
    )
    assert not updated[0].suppressed, "'jfs' must not match inside 'mjfsx'"
