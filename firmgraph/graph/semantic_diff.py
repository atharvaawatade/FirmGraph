"""Semantic diff: the release-over-release story a human can read.

The raw node-set diff (repository.diff) answers "which content-addressed nodes
changed". This layer answers what a device maker actually asks:

    "openssl 1.0.2u -> 3.0.1, 14 CVEs resolved, 2 new criticals"

The one honesty rule no incumbent handles: if the vulnerability DB snapshot
differs between the two scans, CVE deltas are NOT purely the firmware's doing —
some are just the database learning new things. We detect that and say so,
loudly, rather than letting a user read a false "you introduced 5 CVEs".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from firmgraph.graph.repository import GraphRepository


@dataclass(frozen=True)
class ComponentChange:
    name: str
    old_version: str | None
    new_version: str | None

    @property
    def kind(self) -> str:
        if self.old_version is None:
            return "added"
        if self.new_version is None:
            return "removed"
        return "changed"


@dataclass(frozen=True)
class SemanticDiff:
    scan_a: str
    scan_b: str
    components_added: tuple[ComponentChange, ...]
    components_removed: tuple[ComponentChange, ...]
    components_changed: tuple[ComponentChange, ...]
    cves_resolved: tuple[str, ...]
    cves_introduced: tuple[str, ...]
    new_critical_high: tuple[str, ...]
    db_changed: bool
    db_a: str
    db_b: str
    caveats: tuple[str, ...] = field(default_factory=tuple)

    @property
    def empty(self) -> bool:
        return not (
            self.components_added
            or self.components_removed
            or self.components_changed
            or self.cves_resolved
            or self.cves_introduced
        )


def _component_index(repo: GraphRepository, scan_id: str) -> dict[str, str | None]:
    """name -> version (last write wins; components are unique by name in a scan)."""
    index: dict[str, str | None] = {}
    for node in repo.nodes_of_kind(scan_id, "component"):
        name = node.get("name")
        if name:
            index[str(name)] = node.get("version")
    return index


def _finding_index(repo: GraphRepository, scan_id: str) -> dict[str, str]:
    """finding_id -> severity, for CVE-kind findings only."""
    index: dict[str, str] = {}
    for node in repo.nodes_of_kind(scan_id, "finding"):
        if node.get("kind") != "cve":
            continue
        fid = node.get("finding_id")
        if fid:
            index[str(fid)] = str(node.get("severity", "unknown"))
    return index


def _db_snapshot(repo: GraphRepository, scan_id: str) -> str:
    manifest = repo.manifest(scan_id)
    if not manifest:
        return "unknown"
    for snap in manifest.get("db_snapshots", []) or []:
        if str(snap.get("name", "")).endswith("-db"):
            return str(snap.get("version", "unknown"))
    return "unknown"


def semantic_diff(repo: GraphRepository, scan_a: str, scan_b: str) -> SemanticDiff:
    comps_a = _component_index(repo, scan_a)
    comps_b = _component_index(repo, scan_b)

    added, removed, changed = [], [], []
    for name in sorted(comps_b.keys() - comps_a.keys()):
        added.append(ComponentChange(name, None, comps_b[name]))
    for name in sorted(comps_a.keys() - comps_b.keys()):
        removed.append(ComponentChange(name, comps_a[name], None))
    for name in sorted(comps_a.keys() & comps_b.keys()):
        if comps_a[name] != comps_b[name]:
            changed.append(ComponentChange(name, comps_a[name], comps_b[name]))

    finds_a = _finding_index(repo, scan_a)
    finds_b = _finding_index(repo, scan_b)
    resolved = tuple(sorted(finds_a.keys() - finds_b.keys()))
    introduced = tuple(sorted(finds_b.keys() - finds_a.keys()))
    new_crit_high = tuple(
        fid for fid in introduced if finds_b[fid] in ("critical", "high")
    )

    db_a, db_b = _db_snapshot(repo, scan_a), _db_snapshot(repo, scan_b)
    db_changed = db_a != db_b and "unknown" not in (db_a, db_b)

    caveats: list[str] = []
    if db_changed:
        caveats.append(
            f"Vulnerability DB snapshot differs ({db_a} -> {db_b}): some CVE deltas "
            "reflect database updates, NOT firmware changes. Re-scan the old image "
            "against the current DB for a firmware-only comparison."
        )
    elif "unknown" in (db_a, db_b):
        caveats.append(
            "DB snapshot date unavailable for one or both scans — CVE deltas cannot "
            "be attributed to firmware changes with certainty."
        )

    return SemanticDiff(
        scan_a=scan_a,
        scan_b=scan_b,
        components_added=tuple(added),
        components_removed=tuple(removed),
        components_changed=tuple(changed),
        cves_resolved=resolved,
        cves_introduced=introduced,
        new_critical_high=new_crit_high,
        db_changed=db_changed,
        db_a=db_a,
        db_b=db_b,
        caveats=tuple(caveats),
    )
