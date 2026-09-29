"""GraphRepository: the only module that speaks SQL (Repository pattern).

SQLite, WAL mode, zero-config. Nodes are content-addressed; scans are rows;
diff between two scans is a set operation over node ids.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    image_sha256 TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    manifest     TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
    scan_id  TEXT NOT NULL REFERENCES scans(scan_id),
    node_id  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    content  TEXT NOT NULL,
    PRIMARY KEY (scan_id, node_id)
);
CREATE TABLE IF NOT EXISTS edges (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    src     TEXT NOT NULL,
    dst     TEXT NOT NULL,
    kind    TEXT NOT NULL,
    PRIMARY KEY (scan_id, src, dst, kind)
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(scan_id, kind);
"""


@dataclass(frozen=True)
class NodeDelta:
    kind: str
    node_id: str
    summary: str


@dataclass(frozen=True)
class DiffResult:
    scan_a: str
    scan_b: str
    added: tuple[NodeDelta, ...]
    removed: tuple[NodeDelta, ...]

    @property
    def empty(self) -> bool:
        return not self.added and not self.removed


class GraphRepository:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # -- writes ------------------------------------------------------------
    def record_scan(self, scan_id: str, image_sha256: str, created_at: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans(scan_id, image_sha256, created_at) VALUES (?,?,?)",
            (scan_id, image_sha256, created_at),
        )
        self._conn.commit()

    def save_manifest(self, scan_id: str, manifest_json: str) -> None:
        self._conn.execute(
            "UPDATE scans SET manifest=? WHERE scan_id=?", (manifest_json, scan_id)
        )
        self._conn.commit()

    def save_nodes(self, scan_id: str, nodes: list[tuple[str, str, str]]) -> None:
        """nodes: (node_id, kind, canonical_content_json) — sorted by caller for determinism."""
        self._conn.executemany(
            "INSERT OR IGNORE INTO nodes(scan_id, node_id, kind, content) VALUES (?,?,?,?)",
            [(scan_id, n, k, c) for n, k, c in nodes],
        )
        self._conn.commit()

    def save_edges(self, scan_id: str, edges: list[tuple[str, str, str]]) -> None:
        self._conn.executemany(
            "INSERT OR IGNORE INTO edges(scan_id, src, dst, kind) VALUES (?,?,?,?)",
            [(scan_id, s, d, k) for s, d, k in edges],
        )
        self._conn.commit()

    # -- reads ---------------------------------------------------------------
    def scans(self) -> list[tuple[str, str, str]]:
        rows = self._conn.execute(
            "SELECT scan_id, image_sha256, created_at FROM scans ORDER BY created_at"
        ).fetchall()
        return [(str(a), str(b), str(c)) for a, b, c in rows]

    def node_ids(self, scan_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT node_id FROM nodes WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return {str(r[0]) for r in rows}

    def _nodes_by_id(self, scan_id: str) -> dict[str, tuple[str, str]]:
        rows = self._conn.execute(
            "SELECT node_id, kind, content FROM nodes WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return {str(n): (str(k), str(c)) for n, k, c in rows}

    def nodes_of_kind(self, scan_id: str, kind: str) -> list[dict[str, Any]]:
        """Decoded node contents of one kind, sorted by node_id for determinism."""
        rows = self._conn.execute(
            "SELECT node_id, content FROM nodes WHERE scan_id=? AND kind=? ORDER BY node_id",
            (scan_id, kind),
        ).fetchall()
        return [json.loads(str(content)) for _, content in rows]

    def manifest(self, scan_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT manifest FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row is None or row[0] is None:
            return None
        decoded: dict[str, Any] = json.loads(str(row[0]))
        return decoded

    def exists(self, scan_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        return row is not None

    # -- diff: the release-over-release story --------------------------------
    def diff(self, scan_a: str, scan_b: str) -> DiffResult:
        a, b = self._nodes_by_id(scan_a), self._nodes_by_id(scan_b)
        added = tuple(
            _delta(nid, b[nid]) for nid in sorted(b.keys() - a.keys())
        )
        removed = tuple(
            _delta(nid, a[nid]) for nid in sorted(a.keys() - b.keys())
        )
        return DiffResult(scan_a=scan_a, scan_b=scan_b, added=added, removed=removed)


def _delta(nid: str, kind_content: tuple[str, str]) -> NodeDelta:
    kind, content = kind_content
    data: dict[str, Any] = json.loads(content)
    summary = (
        data.get("finding_id")
        or (f"{data.get('name')}@{data.get('version')}" if data.get("name") else None)
        or data.get("sha256", "")[:12]
        or nid[:12]
    )
    return NodeDelta(kind=kind, node_id=nid, summary=str(summary))
