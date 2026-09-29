"""Checks engine exit-gate tests: seeded findings caught, clean tree stays clean,
secrets redacted, deterministic order."""

from __future__ import annotations

import os
from pathlib import Path

from firmgraph.checks import ChecksEngine

FAKE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7c3TROUBLE\n-----END RSA PRIVATE KEY-----\n"
ROOT_HASH = "root:$1$abcdefgh$C0mpr0m1sedHashValue:19000:0:99999:7:::\n"


def _doctored(root: Path) -> Path:
    etc = root / "rootfs" / "etc"
    (etc / "init.d").mkdir(parents=True)
    (etc / "ssl").mkdir()
    (etc / "ssl" / "device.key").write_text(FAKE_KEY)
    (etc / "shadow").write_text(ROOT_HASH)
    (etc / "inittab").write_text("::respawn:/usr/sbin/telnetd -l /bin/login\n")
    (etc / "init.d" / "S99cloud").write_text("API_KEY=AKIA0123456789ABCDEF curl upload\n")
    (etc / "sshd_config").write_text("Port 22\nPermitRootLogin yes\nPermitEmptyPasswords yes\n")
    ww = etc / "config.dat"
    ww.write_text("x")
    os.chmod(ww, 0o666)
    return root


def _clean(root: Path) -> Path:
    etc = root / "rootfs" / "etc"
    (etc / "init.d").mkdir(parents=True)
    (etc / "shadow").write_text("root:*:19000:0:99999:7:::\n")  # locked root — fine
    (etc / "inittab").write_text("::sysinit:/etc/init.d/rcS\n# telnetd disabled\n")
    (etc / "sshd_config").write_text("PermitRootLogin no\nPermitEmptyPasswords no\n")
    (etc / "init.d" / "S10boot").write_text("#!/bin/sh\nmount -a\n")
    return root


def test_doctored_tree_catches_all_seeded(tmp_path: Path) -> None:
    findings = ChecksEngine().run(_doctored(tmp_path))
    rule_ids = {f.finding_id.split("@")[0] for f in findings}
    assert rule_ids >= {
        "FG-SECRET-001",  # private key
        "FG-SECRET-002",  # root hash
        "FG-SECRET-003",  # AWS key
        "FG-CONFIG-001",  # telnetd
        "FG-CONFIG-002",  # PermitRootLogin
        "FG-CONFIG-003",  # PermitEmptyPasswords
        "FG-CONFIG-004",  # world-writable /etc file
    }


def test_clean_tree_zero_findings(tmp_path: Path) -> None:
    findings = ChecksEngine().run(_clean(tmp_path))
    assert findings == [], f"clean tree must stay clean, got: {[f.finding_id for f in findings]}"


def test_secrets_are_redacted(tmp_path: Path) -> None:
    findings = ChecksEngine().run(_doctored(tmp_path))
    blob = "\n".join(f.summary for f in findings)
    assert "MIIEowIBAAKCAQEA7c3TROUBLE" not in blob, "key material must never enter a finding"
    assert "C0mpr0m1sedHashValue" not in blob, "password hash must never enter a finding"
    assert "AKIA0123456789ABCDEF" not in blob, "AWS key must never enter a finding"
    assert "[REDACTED]" in blob
    # non-secret config evidence stays readable — that's useful, and safe
    assert "telnetd" in blob


def test_deterministic_order(tmp_path: Path) -> None:
    a = [f.finding_id for f in ChecksEngine().run(_doctored(tmp_path / "a"))]
    b = [f.finding_id for f in ChecksEngine().run(_doctored(tmp_path / "b"))]
    assert [x.split("@")[0] for x in a] == [x.split("@")[0] for x in b]


def test_binary_files_never_content_scanned(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "blob.bin").write_bytes(b"\x00\x01" + FAKE_KEY.encode() + b"\x00")
    findings = ChecksEngine().run(tmp_path)
    assert all(not f.finding_id.startswith("FG-SECRET-001") for f in findings)
