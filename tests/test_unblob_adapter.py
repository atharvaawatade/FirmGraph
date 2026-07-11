"""Regression guard for the read-only-CWD extraction bug.

unblob writes unblob.log to its working directory. If that dir is read-only —
which happens under our own recommended usage `-v "$PWD:/work:ro"` — extraction
crashes with OSError. The native adapter must run unblob from a writable dir.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from firmgraph.adapters.unblob import UnblobNativeAdapter


def test_native_unblob_runs_from_writable_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    class _Result:
        returncode = 0
        stdout = "Chunk identification ratio: 100.00%"
        stderr = ""

    def fake_run(cmd: list[str], **kwargs: Any) -> _Result:
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(subprocess, "run", fake_run)

    dest = tmp_path / "extracted" / "unblob"
    UnblobNativeAdapter().extract(tmp_path / "fw.bin", dest)

    assert "cwd" in captured, "native unblob must be given an explicit cwd"
    assert captured["cwd"] == str(dest.parent), "cwd must be a writable dir outside the swept extraction dir"
