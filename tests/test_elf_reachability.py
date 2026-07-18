"""ELF linkage reachability (Rung 2) tests.

Coverage strategy: the load-closure ALGORITHM (where bugs hide) is tested directly with
synthetic linkage graphs; the pyelftools I/O is exercised against a hand-crafted REAL
minimal ELF (the `minimal_elf` fixture in conftest.py) so the parser is proven, not mocked;
and the graceful/NOT-APPLICABLE paths (non-ELF, no ELF, pyelftools absent) are asserted.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from firmgraph.enrich import elf_reachability as er
from firmgraph.enrich.elf_reachability import (
    ElfInfo,
    _linked_closure,
    _normalize,
    _parse_elf,
    analyze_elf_linkage,
)
from firmgraph.models import Finding


def test_parse_real_elf(
    tmp_path: Path, minimal_elf: Callable[[str, list[str]], bytes]
) -> None:
    p = tmp_path / "libmylib.so.2"
    p.write_bytes(minimal_elf("mylib.so", ["libc.so.6", "libssl.so.1.1"]))
    info = _parse_elf(p, "usr/lib/libmylib.so.2")
    assert info is not None, "the crafted ELF must actually parse (parser is proven, not mocked)"
    assert info.soname == "mylib.so"
    assert info.needed == frozenset({"libc", "libssl"})
    assert "libmylib" in info.provides and "mylib" in info.provides


def test_parse_non_elf_returns_none(tmp_path: Path) -> None:
    txt = tmp_path / "notelf"
    txt.write_text("#!/bin/sh\necho hi\n")
    assert _parse_elf(txt, "usr/bin/notelf") is None


def test_normalize_strips_version_suffix() -> None:
    assert _normalize("libssl.so.1.1") == "libssl"
    assert _normalize("/usr/lib/libcrypto.so.3") == "libcrypto"


def test_linked_closure_is_transitive() -> None:
    infos = [
        ElfInfo(None, frozenset({"libcurl"}), frozenset({"app"}), is_root=True),
        ElfInfo("libcurl.so.4", frozenset({"libssl"}), frozenset({"libcurl"}), is_root=False),
        ElfInfo("libssl.so.1.1", frozenset(), frozenset({"libssl"}), is_root=False),
        ElfInfo("libz.so.1", frozenset(), frozenset({"libz"}), is_root=False),  # unlinked
    ]
    linked = _linked_closure(infos)
    assert "libcurl" in linked and "libssl" in linked, "transitive: app -> libcurl -> libssl"
    assert "libz" not in linked, "nothing links libz -> not in the load closure"


def _synthetic_infos() -> list[ElfInfo]:
    return [
        ElfInfo(None, frozenset({"libcurl"}), frozenset({"app"}), is_root=True),
        ElfInfo("libcurl.so.4", frozenset({"libssl"}), frozenset({"libcurl"}), is_root=False),
        ElfInfo("libssl.so.1.1", frozenset(), frozenset({"libssl"}), is_root=False),
        ElfInfo("libcrypto.so.1.1", frozenset(), frozenset({"libcrypto"}), is_root=False),
        ElfInfo("libz.so.1", frozenset(), frozenset({"libz"}), is_root=False),  # unlinked
    ]


def test_analyze_confirms_and_downgrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(er, "_collect", lambda _extracted: _synthetic_infos())
    findings = [
        Finding(finding_id="CVE-SSL", kind="cve", severity="high", component="openssl@1.1.1"),
        Finding(finding_id="CVE-ZLIB", kind="cve", severity="high", component="zlib@1.2.11"),
        Finding(finding_id="CVE-BB", kind="cve", severity="high", component="busybox@1.30"),
        Finding(finding_id="CVE-KERN", kind="cve", severity="high", component="linux@5.4"),
    ]
    updated, note = analyze_elf_linkage(Path("/nonexistent"), findings)
    by = {f.finding_id: f for f in updated}
    assert by["CVE-SSL"].reachable is True, "libssl is in the load closure -> confirmed"
    assert by["CVE-ZLIB"].reachable is False, "libz present but unlinked -> downgraded"
    assert by["CVE-BB"].reachable is None, "not present as an ELF library -> left untouched"
    assert by["CVE-KERN"].reachable is None, "kernel finding is not a library -> untouched"
    assert "confirmed 1" in note and "downgraded 1" in note


def test_no_elf_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("no binaries here")
    updated, note = analyze_elf_linkage(
        tmp_path, [Finding(finding_id="CVE-X", kind="cve", severity="high", component="openssl@1")]
    )
    assert updated[0].reachable is None
    assert "NOT APPLICABLE" in note and "no ELF" in note


def test_pyelftools_absent_is_not_applicable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(er, "_HAVE_PYELFTOOLS", False)
    updated, note = analyze_elf_linkage(
        Path("/x"), [Finding(finding_id="CVE-X", kind="cve", severity="high", component="openssl@1")]
    )
    assert updated[0].reachable is None
    assert "NOT APPLICABLE" in note and "pyelftools" in note
