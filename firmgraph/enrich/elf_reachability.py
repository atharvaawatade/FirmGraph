"""ELF linkage reachability (Rung 2) — 'present' is not 'used'.

Practical Binary Analysis, ch. 2: an ELF binary's ``DT_NEEDED`` entries name the shared
libraries it actually links, and ``DT_SONAME`` is the name a library answers to. A
firmware image routinely ships libraries that NOTHING in the active binary set links —
leftover from the build, or shadowed by a statically-linked busybox. Filesystem presence
says "libssl.so is here"; linkage says "…but no running binary loads it." The second is
the truer signal, and it's a cheap, honest step up from the presence heuristic.

What it does, and only this:
- parse every ELF in the rootfs for ``DT_SONAME`` + ``DT_NEEDED`` (all architectures, via
  pyelftools — MIPS/ARM/x86, 32- or 64-bit, either endianness);
- from the executables in PATH-like directories, walk ``DT_NEEDED`` transitively to the
  set of libraries actually reachable by the dynamic loader;
- a library component that is present but OUTSIDE that set is marked ``reachable=False``
  (VEX will call it ``under_investigation`` — a heuristic is not proof); a linked one is
  confirmed ``reachable=True``.

Honest limits (documented, never hidden): ``dlopen()`` and proprietary loaders are
invisible here; statically-linked code has no ``DT_NEEDED``, so we make no claim about it
(no ELF, no verdict); if pyelftools is unavailable or the image holds no ELF, this stage
is NOT APPLICABLE and stays silent. We only ever refine LIBRARY findings for which we have
positive ELF evidence — executables, kernel, and secret findings are left untouched.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from firmgraph.models import Finding

try:  # graceful degradation is the codebase contract: no hard dep at import time
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile

    _HAVE_PYELFTOOLS = True
except Exception:  # pragma: no cover - exercised only where the wheel is missing
    _HAVE_PYELFTOOLS = False

_PATH_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/local/bin/", "usr/local/sbin/")
_MAX_ELF_BYTES = 64 * 1024 * 1024
# component -> the library base names it ships as (curated, honest; mirrors reachability)
_LIB_ALIASES: dict[str, tuple[str, ...]] = {
    "openssl": ("libssl", "libcrypto"),
    "zlib": ("libz",),
    "curl": ("libcurl",),
    "libcurl": ("libcurl",),
    "libxml2": ("libxml2",),
    "sqlite": ("libsqlite3",),
    "sqlite3": ("libsqlite3",),
    "ncurses": ("libncurses",),
    "readline": ("libreadline",),
    "pcre": ("libpcre",),
}


@dataclass(frozen=True)
class ElfInfo:
    soname: str | None
    needed: frozenset[str]  # normalized DT_NEEDED base names
    provides: frozenset[str]  # normalized names this file answers to (soname + filename)
    is_root: bool  # an executable in a PATH-like dir — a closure entry point


def _normalize(name: str) -> str:
    """libssl.so.1.1 -> libssl ; keeps matching robust across version suffixes."""
    base = os.path.basename(name)
    cut = base.split(".so")[0]
    return cut or base


def _parse_elf(path: Path, rel: str) -> ElfInfo | None:
    """Return linkage facts for one ELF file, or None if it isn't a parseable ELF."""
    try:
        with path.open("rb") as fh:
            if fh.read(4) != b"\x7fELF":
                return None
            fh.seek(0)
            elf = ELFFile(fh)
            soname: str | None = None
            needed: set[str] = set()
            for section in elf.iter_sections():
                if not isinstance(section, DynamicSection):
                    continue
                for tag in section.iter_tags():
                    # pyelftools has no stubs; DT_NEEDED/DT_SONAME expose the resolved
                    # string via dynamic attributes (.needed/.soname) — view as Any.
                    t: Any = tag
                    if t.entry.d_tag == "DT_NEEDED":
                        needed.add(_normalize(str(t.needed)))
                    elif t.entry.d_tag == "DT_SONAME":
                        soname = str(t.soname)
    except Exception:
        return None  # truncated / exotic / not really an ELF — skip it, honestly

    fname = os.path.basename(rel)
    provides = {_normalize(fname)}
    if soname:
        provides.add(_normalize(soname))
    return ElfInfo(
        soname=soname,
        needed=frozenset(needed),
        provides=frozenset(provides),
        is_root=any(seg in f"{rel}/" for seg in _PATH_DIRS) and not fname.startswith("lib"),
    )


def _collect(extracted: Path) -> list[ElfInfo]:
    infos: list[ElfInfo] = []
    for dirpath, _dirnames, filenames in os.walk(extracted, followlinks=False):
        d = Path(dirpath)
        for fn in filenames:
            p = d / fn
            try:
                if not p.is_file() or p.is_symlink() or p.stat().st_size > _MAX_ELF_BYTES:
                    continue
            except OSError:
                continue
            info = _parse_elf(p, str(p.relative_to(extracted)))
            if info is not None:
                infos.append(info)
    return infos


def _linked_closure(infos: list[ElfInfo]) -> set[str]:
    """Transitive set of normalized library names reachable from the executables."""
    providers: dict[str, frozenset[str]] = {}
    for info in infos:
        for name in info.provides:
            # union the needs of everything answering to this name
            providers[name] = providers.get(name, frozenset()) | info.needed

    reachable: set[str] = set()
    frontier: set[str] = set()
    for info in infos:
        if info.is_root:
            frontier |= set(info.needed)
    while frontier:
        name = frontier.pop()
        if name in reachable:
            continue
        reachable.add(name)
        frontier |= set(providers.get(name, frozenset())) - reachable
    return reachable


def _lib_names(component: str) -> tuple[str, ...]:
    name = component.split("@")[0].strip().lower()
    if name in _LIB_ALIASES:
        return _LIB_ALIASES[name]
    return (name, f"lib{name}")


def analyze_elf_linkage(
    extracted: Path, findings: list[Finding]
) -> tuple[list[Finding], str]:
    """Refine LIBRARY findings by real dynamic linkage. Returns (findings, note)."""
    if not _HAVE_PYELFTOOLS:
        return list(findings), (
            "elf-linkage: NOT APPLICABLE — pyelftools not installed; dynamic-linkage "
            "reachability skipped (no claim made)"
        )
    infos = _collect(extracted)
    if not infos:
        return list(findings), (
            "elf-linkage: NOT APPLICABLE — no ELF binaries found (statically-linked or "
            "non-ELF image); presence heuristic stands"
        )

    present = {name for info in infos for name in info.provides}
    linked = _linked_closure(infos)

    updated: list[Finding] = []
    confirmed = downgraded = 0
    for f in findings:
        if f.kind != "cve" or f.suppressed or not f.component:
            updated.append(f)
            continue
        libs = _lib_names(f.component)
        present_libs = [lib for lib in libs if lib in present]
        if not present_libs:
            updated.append(f)  # not a library we have ELF evidence for — leave it
            continue
        if any(lib in linked for lib in present_libs):
            updated.append(f.model_copy(update={"reachable": True}))
            confirmed += 1
        else:
            # present in the image, but no executable links it -> not loaded
            updated.append(f.model_copy(update={"reachable": False}))
            downgraded += 1

    return updated, (
        f"elf-linkage: {len(infos)} ELF binaries, {len(linked)} libraries in the load "
        f"closure — confirmed {confirmed} reachable, downgraded {downgraded} "
        f"present-but-unlinked (dlopen/proprietary loaders excluded by design)"
    )
