"""Kernel-config-aware CVE filtering — THE noise-killer, stated honestly.

The Linux kernel version-match problem: matching a kernel version yields ~thousands
of CVEs, most of them in subsystems that were never compiled into THIS firmware. A
headless router has no GPU, no sound, no Bluetooth, no exotic filesystems — yet a
version match floods it with drm/, sound/, net/bluetooth/, fs/btrfs/ CVEs. That flood
is exactly the "3,000 findings" firehose our whole thesis says we kill.

This module reads the kernel's OWN build config out of the extracted image and marks
CVEs in provably-absent subsystems as ``suppressed`` — WITH the exact config line as
proof. Suppressed (not deleted) means it flows straight into VEX as ``not_affected``
(impact_statement = the proof) and sinks to the bottom of the ranked report, never
vanishing from the audit trail.

Honesty discipline — the entire point of this module:
- We suppress ONLY on positive proof of absence: an explicit ``# CONFIG_X is not set``
  line, or a *complete* kernel config in which the gating symbol is absent. If a symbol
  might be enabled, we say nothing.
- If no kernel config is found: NOT APPLICABLE — every finding is left untouched and we
  say so. An RTOS, a stripped image, or a kernel built without CONFIG_IKCONFIG gets
  silence, not false reassurance.
- We map a CVE to a subsystem via conservative signals in its description — heavily
  biased to source-path fragments (``drivers/gpu/drm``, ``fs/xfs``, ``net/bluetooth``)
  that modern kernel CVE descriptions almost always carry, because those are far more
  precise than a bare word. A miss leaves the finding fully active.

A crude *true* suppression beats a confident *false* one. When in doubt, we keep it.
"""

from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass
from pathlib import Path

from firmgraph.models import Finding

# --- parsing a kernel .config -------------------------------------------------
_CONFIG_SET_RE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=[ym]", re.MULTILINE)
_CONFIG_UNSET_RE = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set", re.MULTILINE)
_MAX_CONFIG_BYTES = 8 * 1024 * 1024
# a fragment with this many lines total is a real config, not an incidental file
_MIN_CONFIG_LINES = 20
# a real, whole ``.config`` lists hundreds of "is not set" lines; that completeness
# is what lets us treat an *absent* symbol as *disabled*. A short fragment cannot.
_COMPLETE_UNSET_FLOOR = 50


@dataclass(frozen=True)
class KernelConfig:
    """A parsed kernel build config + where it came from (the proof source)."""

    source: str  # relative path we read it from — cited in every suppression
    enabled: frozenset[str]  # CONFIG_ symbols set to =y or =m
    disabled: frozenset[str]  # CONFIG_ symbols explicitly "# ... is not set"
    complete: bool  # True => a whole config, so "absent" can be read as "disabled"

    def gate_off(self, configs: tuple[str, ...]) -> tuple[bool, str]:
        """Is a subsystem provably OFF? True only if EVERY gating symbol is proven
        disabled — by an explicit unset line, or absence from a complete config.
        Returns (off, proof). If any gate might be on, returns (False, "")."""
        proofs: list[str] = []
        for c in configs:
            if c in self.disabled:
                proofs.append(f"# {c} is not set")
            elif self.complete and c not in self.enabled:
                proofs.append(f"{c} absent from complete kernel config")
            else:
                return False, ""  # enabled, or unknown in an incomplete config
        return True, "; ".join(proofs)


# --- the subsystem map: keyword (in CVE description) -> gating CONFIG symbol ---
# Keywords are biased to source-path fragments (high precision). Bare names are
# matched on word boundaries only (see _keyword_hit) so "hfs"/"udf"/"jfs" can't
# collide with unrelated text. Curated toward the families most often ABSENT on
# embedded network devices — where the honest, high-yield suppressions live.
@dataclass(frozen=True)
class _Subsystem:
    name: str
    configs: tuple[str, ...]
    keywords: tuple[str, ...]


_SUBSYSTEMS: tuple[_Subsystem, ...] = (
    _Subsystem("Bluetooth", ("CONFIG_BT",),
               ("net/bluetooth", "bluetooth", "l2cap", "rfcomm", "hci_uart", "hidp")),
    _Subsystem("WiFi (mac80211/cfg80211)", ("CONFIG_WLAN", "CONFIG_CFG80211"),
               ("net/mac80211", "net/wireless", "mac80211", "cfg80211", "nl80211")),
    _Subsystem("GPU/DRM", ("CONFIG_DRM",),
               ("drivers/gpu/drm", "drm/", "amdgpu", "i915", "nouveau", "radeon", "vmwgfx")),
    _Subsystem("Sound/ALSA", ("CONFIG_SND",),
               ("sound/", "alsa", "snd_", "soundcore")),
    _Subsystem("NFC", ("CONFIG_NFC",),
               ("net/nfc", "nfc/")),
    _Subsystem("InfiniBand/RDMA", ("CONFIG_INFINIBAND",),
               ("drivers/infiniband", "infiniband", "rdma")),
    _Subsystem("KVM virtualization", ("CONFIG_KVM",),
               ("arch/x86/kvm", "virt/kvm", "kvm/")),
    _Subsystem("Xen", ("CONFIG_XEN",),
               ("drivers/xen", "xen/", "xen-netback", "xen-blkback")),
    _Subsystem("Hyper-V", ("CONFIG_HYPERV",),
               ("hyper-v", "hyperv", "drivers/hv/")),
    _Subsystem("CAN bus", ("CONFIG_CAN",),
               ("net/can", "j1939")),
    _Subsystem("Media/V4L2/DVB", ("CONFIG_MEDIA_SUPPORT",),
               ("drivers/media", "v4l2", "videobuf", "/dvb")),
    _Subsystem("Framebuffer", ("CONFIG_FB",),
               ("drivers/video/fbdev", "framebuffer", "fbcon")),
    _Subsystem("XFS filesystem", ("CONFIG_XFS_FS",), ("fs/xfs", "xfs")),
    _Subsystem("Btrfs filesystem", ("CONFIG_BTRFS_FS",), ("fs/btrfs", "btrfs")),
    _Subsystem("F2FS filesystem", ("CONFIG_F2FS_FS",), ("fs/f2fs", "f2fs")),
    _Subsystem("NTFS filesystem", ("CONFIG_NTFS_FS", "CONFIG_NTFS3_FS"), ("fs/ntfs", "ntfs")),
    _Subsystem("ReiserFS filesystem", ("CONFIG_REISERFS_FS",), ("fs/reiserfs", "reiserfs")),
    _Subsystem("HFS/HFS+ filesystem", ("CONFIG_HFS_FS", "CONFIG_HFSPLUS_FS"),
               ("fs/hfs", "hfsplus", "hfs")),
    _Subsystem("JFS filesystem", ("CONFIG_JFS_FS",), ("fs/jfs", "jfs")),
    _Subsystem("GFS2 filesystem", ("CONFIG_GFS2_FS",), ("fs/gfs2", "gfs2")),
    _Subsystem("OCFS2 filesystem", ("CONFIG_OCFS2_FS",), ("fs/ocfs2", "ocfs2")),
    _Subsystem("UDF filesystem", ("CONFIG_UDF_FS",), ("fs/udf", "udf")),
    _Subsystem("USB gadget", ("CONFIG_USB_GADGET",), ("drivers/usb/gadget", "usb gadget")),
    _Subsystem("SCSI target", ("CONFIG_TARGET_CORE",), ("drivers/target", "target_core")),
)

_KERNEL_COMPONENTS = {"linux", "kernel", "linux_kernel", "linux-kernel", "vmlinux"}


def _keyword_hit(text: str, keyword: str) -> bool:
    """Path fragments and long tokens match as substrings (precise); short bare
    words match only on word boundaries so they can't collide with unrelated text."""
    if "/" in keyword or len(keyword) > 5:
        return keyword in text
    return re.search(rf"\b{re.escape(keyword)}\b", text) is not None


def _match_subsystem(finding: Finding) -> _Subsystem | None:
    text = f"{finding.summary} {finding.finding_id}".lower()
    if not text.strip():
        return None
    for sub in _SUBSYSTEMS:
        if any(_keyword_hit(text, kw) for kw in sub.keywords):
            return sub
    return None


def _is_kernel_cve(finding: Finding) -> bool:
    if finding.kind != "cve":
        return False
    comp = (finding.component or "").split("@")[0].strip().lower()
    return comp in _KERNEL_COMPONENTS or "kernel" in comp


# --- finding & reading the config out of an extracted image -------------------
def _iter_config_texts(extracted: Path) -> list[tuple[str, str]]:
    """Yield (relative-source, text) for every plausible kernel config in the tree."""
    out: list[tuple[str, str]] = []
    for dirpath, _dirnames, filenames in os.walk(extracted, followlinks=False):
        d = Path(dirpath)
        for fn in filenames:
            p = d / fn
            rel = str(p.relative_to(extracted))
            low = fn.lower()
            try:
                if low == "config.gz" and "proc" in rel.lower():
                    if p.stat().st_size > _MAX_CONFIG_BYTES:
                        continue
                    with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as fh:
                        out.append((rel, fh.read(_MAX_CONFIG_BYTES)))
                elif low.startswith("config-") or low == ".config" or (
                    low == "config" and "linux" in rel.lower()
                ):
                    if p.is_file() and p.stat().st_size <= _MAX_CONFIG_BYTES:
                        out.append((rel, p.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
    return out


def extract_kernel_config(extracted: Path) -> KernelConfig | None:
    """Return the most-complete kernel config found in the image, or None."""
    best: KernelConfig | None = None
    for source, text in _iter_config_texts(extracted):
        enabled = frozenset(m.group(1) for m in _CONFIG_SET_RE.finditer(text))
        disabled = frozenset(m.group(1) for m in _CONFIG_UNSET_RE.finditer(text))
        if len(enabled) + len(disabled) < _MIN_CONFIG_LINES:
            continue  # an incidental file that merely mentions CONFIG_, not a real config
        cfg = KernelConfig(
            source=source,
            enabled=enabled,
            disabled=disabled,
            complete=len(disabled) >= _COMPLETE_UNSET_FLOOR,
        )
        if best is None or len(cfg.disabled) > len(best.disabled):
            best = cfg
    return best


def analyze_kernel_config(
    extracted: Path, findings: list[Finding]
) -> tuple[list[Finding], str]:
    """Suppress kernel CVEs in provably-disabled subsystems. Returns (findings, note)."""
    cfg = extract_kernel_config(extracted)
    if cfg is None:
        return list(findings), (
            "kernel-config: NOT APPLICABLE — no kernel build config found "
            "(no /proc/config.gz or boot config); no suppression, silence over "
            "false reassurance"
        )

    updated: list[Finding] = []
    suppressed = 0
    for f in findings:
        if f.suppressed or not _is_kernel_cve(f):
            updated.append(f)
            continue
        sub = _match_subsystem(f)
        if sub is None:
            updated.append(f)
            continue
        off, proof = cfg.gate_off(sub.configs)
        if not off:
            updated.append(f)
            continue
        reason = (
            f"kernel-config: {sub.name} not compiled into this kernel "
            f"({proof}; source: {cfg.source})"
        )
        updated.append(f.model_copy(update={"suppressed": True, "suppression_reason": reason}))
        suppressed += 1

    kernel_total = sum(1 for f in findings if _is_kernel_cve(f))
    return updated, (
        f"kernel-config: applied ({cfg.source}, complete={cfg.complete}, "
        f"{len(cfg.enabled)} enabled / {len(cfg.disabled)} disabled symbols) — "
        f"suppressed {suppressed}/{kernel_total} kernel CVEs in absent subsystems, "
        f"each with the config line as proof"
    )
