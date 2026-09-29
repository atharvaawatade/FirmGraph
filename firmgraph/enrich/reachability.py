"""Reachability — a LINUX-FILESYSTEM HEURISTIC, stated as such, never oversold.

What it actually does (and all it does):
- detects Linux rootfs markers (init.d / rcS / inittab / systemd units / sbin/init);
- if absent: every finding keeps ``reachable=None`` — the heuristic is
  NOT APPLICABLE and says so (RTOS/monolithic images get silence, not lies);
- if present, a component is "reachable" when its binary sits in a PATH-like
  directory, its library lives in a lib directory, or an init/service file
  references it by name.

It will miss dlopen()-style loading and proprietary launchers — that is
documented, not hidden. A crude true signal beats a confident false one.
"""

from __future__ import annotations

import os
from pathlib import Path

from firmgraph.models import Finding

_INIT_MARKERS = (
    "etc/init.d",
    "etc/rc.d",
    "etc/inittab",
    "etc/rcS",
    "sbin/init",
    "lib/systemd/system",
    "etc/systemd/system",
)
_BIN_DIRS = ("bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin")
_LIB_DIRS = ("lib", "usr/lib", "usr/local/lib", "lib64", "usr/lib64")
# component -> the library names it ships as (small, curated, honest)
_LIB_ALIASES: dict[str, tuple[str, ...]] = {
    "openssl": ("libssl", "libcrypto"),
    "zlib": ("libz",),
    "curl": ("libcurl",),
    "busybox": ("busybox",),
}
_MAX_INIT_BYTES = 512 * 1024  # only small text files are worth grepping


def find_linux_roots(extracted: Path) -> list[Path]:
    """Directories that look like a Linux rootfs (marker-based)."""
    roots: list[Path] = []
    for dirpath, dirnames, _ in os.walk(extracted, followlinks=False):
        d = Path(dirpath)
        if any((d / marker).exists() for marker in _INIT_MARKERS):
            roots.append(d)
            dirnames.clear()  # a rootfs found; don't re-detect its subdirs
    return sorted(roots)


def analyze_reachability(extracted: Path, findings: list[Finding]) -> tuple[list[Finding], str]:
    """Returns (updated findings, honest note)."""
    roots = find_linux_roots(extracted)
    if not roots:
        return list(findings), (
            "reachability: NOT APPLICABLE — no Linux filesystem markers found "
            "(heuristic is silent on RTOS/monolithic images, not falsely reassuring)"
        )

    path_bins: set[str] = set()
    libs: set[str] = set()
    init_text: list[str] = []
    for root in roots:
        for bin_dir in _BIN_DIRS:
            d = root / bin_dir
            if d.is_dir():
                path_bins.update(p.name for p in d.iterdir() if not p.name.startswith("."))
        for lib_dir in _LIB_DIRS:
            d = root / lib_dir
            if d.is_dir():
                libs.update(p.name.split(".so")[0] for p in d.iterdir() if ".so" in p.name)
        for init_source in ("etc/init.d", "etc/rc.d", "lib/systemd/system", "etc/systemd/system"):
            d = root / init_source
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    init_text.append(_read_small(f))
        for single in ("etc/inittab", "etc/rcS"):
            f = root / single
            if f.is_file():
                init_text.append(_read_small(f))
    init_blob = "\n".join(init_text)

    updated: list[Finding] = []
    for finding in findings:
        name = (finding.component or "").split("@")[0].strip().lower()
        if not name:
            updated.append(finding)
            continue
        reachable = (
            name in path_bins
            or any(alias in libs for alias in _LIB_ALIASES.get(name, (name, f"lib{name}")))
            or name in init_blob
        )
        updated.append(finding.model_copy(update={"reachable": reachable}))

    hit = sum(1 for f in updated if f.reachable is True)
    return updated, (
        f"reachability: Linux-filesystem heuristic applied ({len(roots)} rootfs, "
        f"{hit}/{len(updated)} findings reachable) — misses dlopen/proprietary launchers by design"
    )


def _read_small(path: Path) -> str:
    try:
        if path.is_file() and path.stat().st_size <= _MAX_INIT_BYTES:
            return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    return ""
