"""Shared test fixtures — notably a real, minimal ELF builder so ELF-dependent tests
run anywhere (macOS CI has no ELF binaries lying around to borrow)."""

from __future__ import annotations

import struct
from collections.abc import Callable

import pytest


def _minimal_elf(soname: str, needed: list[str]) -> bytes:
    """Bytes of a minimal but genuinely parseable ELF64 shared object carrying
    DT_SONAME + the given DT_NEEDED entries (so pyelftools reads real linkage)."""
    strtab = b"\x00"
    off: dict[str, int] = {}
    for name in [*needed, soname]:
        if name not in off:
            off[name] = len(strtab)
            strtab += name.encode() + b"\x00"

    DT_NEEDED, DT_SONAME, DT_STRSZ, DT_NULL = 1, 14, 10, 0
    dyn = b"".join(struct.pack("<qQ", DT_NEEDED, off[n]) for n in needed)
    dyn += struct.pack("<qQ", DT_SONAME, off[soname])
    dyn += struct.pack("<qQ", DT_STRSZ, len(strtab))
    dyn += struct.pack("<qQ", DT_NULL, 0)

    shstr = b"\x00"
    sname: dict[str, int] = {}
    for nm in (".dynamic", ".dynstr", ".shstrtab"):
        sname[nm] = len(shstr)
        shstr += nm.encode() + b"\x00"

    ehsize = 64
    dyn_off = ehsize
    dynstr_off = dyn_off + len(dyn)
    shstr_off = dynstr_off + len(strtab)
    shtab_off = shstr_off + len(shstr)

    def shdr(nm: int, typ: int, offset: int, size: int, link: int = 0, entsize: int = 0) -> bytes:
        return struct.pack("<IIQQQQIIQQ", nm, typ, 0, 0, offset, size, link, 0, 1, entsize)

    sections = (
        shdr(0, 0, 0, 0)
        + shdr(sname[".dynamic"], 6, dyn_off, len(dyn), link=2, entsize=16)  # SHT_DYNAMIC
        + shdr(sname[".dynstr"], 3, dynstr_off, len(strtab))  # SHT_STRTAB
        + shdr(sname[".shstrtab"], 3, shstr_off, len(shstr))  # SHT_STRTAB
    )
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shtab_off, 0, ehsize, 0, 0, 64, 4, 3
    )
    return ehdr + dyn + strtab + shstr + sections


@pytest.fixture
def minimal_elf() -> Callable[[str, list[str]], bytes]:
    """Factory fixture: ``minimal_elf(soname, needed) -> bytes`` of a parseable ELF64 .so."""
    return _minimal_elf
