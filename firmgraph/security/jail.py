"""Extraction jail (implementation-plan A.4.2): firmware is hostile input.

Extractors run as subprocesses with timeouts; their output directory is then
swept by this module before anything downstream touches it:

- **symlink escape**: any link resolving outside the jail root is removed
  (a crafted squashfs can plant `etc -> /etc` and downstream stages would
  happily walk the host filesystem);
- **decompression budgets**: max file count / total bytes / path depth kill
  zip-bomb-style blowups;
- every violation is recorded loudly — honesty over silence, always.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 200_000
MAX_TOTAL_BYTES = 4 * 1024**3  # 4 GiB
MAX_DEPTH = 48


class JailViolation(Exception):
    """Raised when a path escapes the jail root (traversal guard)."""


def assert_within(root: Path, candidate: Path) -> Path:
    """Traversal guard: resolved candidate must remain under resolved root."""
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise JailViolation(f"path escapes jail: {candidate} -> {resolved}")
    return resolved


@dataclass(frozen=True)
class JailReport:
    files: int
    total_bytes: int
    violations: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.violations


def sweep_jail(
    root: Path,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_depth: int = MAX_DEPTH,
) -> JailReport:
    """Post-extraction sweep: neutralize escapes, enforce budgets, count honestly."""
    violations: list[str] = []
    files = 0
    total_bytes = 0
    resolved_root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_depth = len(Path(dirpath).relative_to(root).parts)
        if rel_depth > max_depth:
            violations.append(f"depth budget exceeded ({rel_depth} > {max_depth}) at {dirpath}")
            dirnames.clear()  # do not descend further
            continue
        for name in list(dirnames):
            candidate = Path(dirpath) / name
            if candidate.is_symlink() and not _link_within(resolved_root, candidate):
                violations.append(f"symlink escape removed (dir): {candidate}")
                candidate.unlink()
                dirnames.remove(name)
        for name in filenames:
            candidate = Path(dirpath) / name
            if candidate.is_symlink():
                if not _link_within(resolved_root, candidate):
                    violations.append(f"symlink escape removed: {candidate}")
                    candidate.unlink()
                continue  # in-jail symlinks are counted as links, not files
            try:
                size = candidate.stat().st_size
            except OSError:
                continue
            files += 1
            total_bytes += size
            if files > max_files:
                violations.append(f"file-count budget exceeded (> {max_files})")
                return JailReport(files=files, total_bytes=total_bytes, violations=tuple(violations))
            if total_bytes > max_total_bytes:
                violations.append(f"byte budget exceeded (> {max_total_bytes})")
                return JailReport(files=files, total_bytes=total_bytes, violations=tuple(violations))

    return JailReport(files=files, total_bytes=total_bytes, violations=tuple(violations))


def _link_within(resolved_root: Path, link: Path) -> bool:
    try:
        target = link.resolve()
    except OSError:
        return False
    return target.is_relative_to(resolved_root)
