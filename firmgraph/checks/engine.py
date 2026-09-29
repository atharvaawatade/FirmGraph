"""Checks engine: YAML-driven secrets / crypto / config rules (Interpreter-lite).

Design commitments (implementation-plan A.4.4 + Phase 5):
- **redaction by default**: a discovered secret's VALUE never enters a finding —
  only its location and a sha256 prefix for correlation. The report must never
  become the leak;
- **deterministic**: sorted walk, sorted rules, one finding per (rule, file);
- **bounded**: content rules only touch text-like files up to a size cap —
  firmware trees hold gigabytes of binaries that regex must never crawl.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from firmgraph.models import Finding

_MAX_CONTENT_KB = 512
_BINARY_SNIFF_BYTES = 1024


@dataclass(frozen=True)
class CheckRule:
    id: str
    kind: str  # "secret" | "crypto" | "config"
    severity: str
    description: str
    pattern: re.Pattern[str] | None = None
    file_globs: tuple[str, ...] = ()
    path_globs: tuple[str, ...] = ()
    world_writable: bool = False
    redact: bool = False


@dataclass
class _FileEntry:
    path: Path
    rel: str
    mode: int
    size: int
    text: str | None = field(default=None, repr=False)


class ChecksEngine:
    def __init__(self, rulepack: Path | None = None) -> None:
        self.rulepack_path = rulepack or Path(__file__).parent / "rulepacks" / "v1.yaml"
        self.version, self.rules = self._load()

    def _load(self) -> tuple[str, list[CheckRule]]:
        doc = yaml.safe_load(self.rulepack_path.read_text(encoding="utf-8")) or {}
        rules: list[CheckRule] = []
        for raw in doc.get("rules", []) or []:
            pattern = raw.get("pattern")
            rules.append(
                CheckRule(
                    id=str(raw["id"]),
                    kind=str(raw.get("kind", "config")),
                    severity=str(raw.get("severity", "medium")),
                    description=str(raw.get("description", raw["id"])),
                    pattern=re.compile(pattern) if pattern else None,
                    file_globs=tuple(raw.get("file_globs", []) or []),
                    path_globs=tuple(raw.get("path_globs", []) or []),
                    world_writable=bool(raw.get("world_writable", False)),
                    redact=bool(raw.get("redact", False)),
                )
            )
        rules.sort(key=lambda r: r.id)
        return str(doc.get("version", "unknown")), rules

    def run(self, extracted: Path) -> list[Finding]:
        findings: list[Finding] = []
        for entry in self._walk(extracted):
            for rule in self.rules:
                finding = self._apply(rule, entry)
                if finding is not None:
                    findings.append(finding)
        findings.sort(key=lambda f: (f.finding_id, f.component or ""))
        return findings

    # -- rule application ------------------------------------------------------
    def _apply(self, rule: CheckRule, entry: _FileEntry) -> Finding | None:
        if rule.world_writable:
            if not _globs_match(rule.path_globs, entry.rel):
                return None
            if entry.mode & 0o002:
                return self._finding(rule, entry, evidence=f"mode {oct(entry.mode & 0o7777)}")
            return None

        if rule.pattern is None:
            return None
        if rule.file_globs and not _globs_match(rule.file_globs, entry.rel):
            return None
        if entry.text is None:
            return None
        match = rule.pattern.search(entry.text)
        if match is None:
            return None
        line_no = entry.text.count("\n", 0, match.start()) + 1
        if rule.redact:
            digest = hashlib.sha256(match.group(0).encode()).hexdigest()[:8]
            evidence = f"line {line_no}; evidence sha256:{digest} [REDACTED]"
        else:
            snippet = match.group(0).strip().replace("\n", " ")[:80]
            evidence = f"line {line_no}: {snippet}"
        return self._finding(rule, entry, evidence)

    def _finding(self, rule: CheckRule, entry: _FileEntry, evidence: str) -> Finding:
        return Finding(
            finding_id=f"{rule.id}@{_short(entry.rel)}",
            kind=rule.kind,
            severity=rule.severity,
            source="checks",
            component=entry.rel,
            summary=f"{rule.description} — {evidence}",
            fix=None,
        )

    # -- bounded, deterministic walk -------------------------------------------
    def _walk(self, extracted: Path) -> list[_FileEntry]:
        entries: list[_FileEntry] = []
        for dirpath, dirnames, filenames in os.walk(extracted, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                rel = path.relative_to(extracted).as_posix()
                entry = _FileEntry(path=path, rel=rel, mode=stat.st_mode, size=stat.st_size)
                if stat.st_size <= _MAX_CONTENT_KB * 1024:
                    entry.text = _read_text(path)
                entries.append(entry)
        return entries


def _globs_match(globs: tuple[str, ...], rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch("/" + rel, g) for g in globs)


def _short(rel: str) -> str:
    """Compact location for finding ids: last 3 path segments."""
    return "/".join(rel.split("/")[-3:])


def _read_text(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(_BINARY_SNIFF_BYTES)
            if b"\x00" in head:
                return None  # binary — content rules never crawl binaries
            rest = fh.read(_MAX_CONTENT_KB * 1024 - len(head))
        return (head + rest).decode("utf-8", errors="ignore")
    except OSError:
        return None
