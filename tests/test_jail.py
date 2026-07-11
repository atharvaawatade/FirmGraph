"""Extraction-jail security tests: firmware is hostile input (plan A.4.2).

These simulate what a malicious image does after extraction: symlinks pointing
at the host filesystem, path traversal, and decompression blowups.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from firmgraph.security.jail import JailViolation, assert_within, sweep_jail


def test_assert_within_allows_inside(tmp_path: Path) -> None:
    inside = tmp_path / "a" / "b.txt"
    inside.parent.mkdir()
    inside.write_text("x")
    assert assert_within(tmp_path, inside) == inside.resolve()


def test_assert_within_blocks_traversal(tmp_path: Path) -> None:
    with pytest.raises(JailViolation):
        assert_within(tmp_path, tmp_path / ".." / "evil.txt")


def test_sweep_removes_symlink_escape(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "ok.txt").write_text("fine")
    escape = jail / "etc"
    escape.symlink_to("/etc")  # the classic: crafted fs planting a link to the host
    report = sweep_jail(jail)
    assert not escape.exists(follow_symlinks=False), "escaping symlink must be removed"
    assert any("symlink escape" in v for v in report.violations)
    assert report.files == 1  # only the real file counted


def test_sweep_keeps_internal_symlinks(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "busybox").write_text("ELF")
    (jail / "sh").symlink_to(jail / "busybox")  # normal firmware idiom
    report = sweep_jail(jail)
    assert report.clean
    assert (jail / "sh").is_symlink()


def test_sweep_enforces_file_budget(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    for i in range(20):
        (jail / f"f{i}").write_text("x")
    report = sweep_jail(jail, max_files=10)
    assert any("file-count budget" in v for v in report.violations)


def test_sweep_enforces_byte_budget(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "bomb").write_bytes(b"\x00" * 4096)
    report = sweep_jail(jail, max_total_bytes=1024)
    assert any("byte budget" in v for v in report.violations)


def test_sweep_enforces_depth_budget(tmp_path: Path) -> None:
    jail = tmp_path / "jail"
    deep = jail
    for i in range(8):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_text("x")
    report = sweep_jail(jail, max_depth=4)
    assert any("depth budget" in v for v in report.violations)


def test_sweep_never_follows_links_into_host(tmp_path: Path) -> None:
    """os.walk(followlinks=False) + removal => host files are never enumerated."""
    outside = tmp_path / "host_secret"
    outside.mkdir()
    (outside / "passwd").write_text("root:x")
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "leak").symlink_to(outside)
    report = sweep_jail(jail)
    assert report.files == 0
    assert any("symlink escape" in v for v in report.violations)
    assert (outside / "passwd").exists(), "host files must never be touched"
    assert os.path.lexists(jail / "leak") is False
