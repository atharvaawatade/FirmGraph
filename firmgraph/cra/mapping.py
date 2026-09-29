"""CRA Annex I mapping — best-effort, deterministic, and honest about its limits.

Language discipline (locked in the product doc): we never say "non-compliant".
A finding "touches" an essential requirement; the manufacturer and their
notified body decide what that means. Harmonised standards are not final —
this table is evidence organisation, not legal interpretation.

Mapping rules are deliberately simple and reviewable:
  cve            -> I.2a (known vulnerabilities) + II.2 (remediate)
  cve, no fix    -> + II.8 (patches without delay — upstream EOL blocks this)
  secret         -> I.2d (unauthorised access) + I.2e (confidentiality)
  crypto         -> I.2e
  config: telnet -> I.2b (secure defaults) + I.2j (attack surface)
  config: ssh    -> I.2b + I.2d
  config: perms  -> I.2f (integrity)
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from firmgraph.models import Finding

MAPPING_DISCLAIMER = (
    "Best-effort mapping to CRA (EU 2024/2847) Annex I essential requirements. "
    "Not legal advice; harmonised standards are not final. A finding 'touching' "
    "a requirement is evidence organisation, not a compliance determination."
)


@dataclass(frozen=True)
class CraRef:
    req_id: str
    title: str


@lru_cache(maxsize=1)
def _requirements() -> dict[str, str]:
    data_path = Path(__file__).parent / "annex1.yaml"
    doc = yaml.safe_load(data_path.read_text(encoding="utf-8")) or {}
    return {
        str(req["id"]): str(req["title"]) for req in doc.get("requirements", []) or []
    }


def _refs(*req_ids: str) -> tuple[CraRef, ...]:
    reqs = _requirements()
    return tuple(CraRef(req_id=r, title=reqs.get(r, r)) for r in req_ids)


def map_finding(finding: Finding) -> tuple[CraRef, ...]:
    """Deterministic finding -> Annex I requirement references."""
    if finding.kind == "cve":
        refs = ["I.2a", "II.2"]
        if finding.fix is None:  # EOL component: the patch obligation is blocked upstream
            refs.append("II.8")
        return _refs(*refs)
    if finding.kind == "secret":
        return _refs("I.2d", "I.2e")
    if finding.kind == "crypto":
        return _refs("I.2e")
    if finding.kind == "config":
        rule = finding.finding_id.split("@")[0]
        if rule == "FG-CONFIG-001":  # telnet at boot
            return _refs("I.2b", "I.2j")
        if rule in ("FG-CONFIG-002", "FG-CONFIG-003"):  # ssh root / empty passwords
            return _refs("I.2b", "I.2d")
        if rule == "FG-CONFIG-004":  # world-writable
            return _refs("I.2f")
        return _refs("I.2b")
    return ()


@dataclass(frozen=True)
class CraRow:
    ref: CraRef
    finding_ids: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.finding_ids)


def aggregate_mapping(findings: list[Finding]) -> list[CraRow]:
    """Requirement -> affected findings, sorted by requirement id. Suppressed excluded."""
    buckets: dict[str, list[str]] = {}
    titles: dict[str, str] = {}
    for finding in findings:
        if finding.suppressed:
            continue
        for ref in map_finding(finding):
            buckets.setdefault(ref.req_id, []).append(finding.finding_id)
            titles[ref.req_id] = ref.title
    return [
        CraRow(
            ref=CraRef(req_id=req_id, title=titles[req_id]),
            finding_ids=tuple(sorted(set(buckets[req_id]))),
        )
        for req_id in sorted(buckets)
    ]
