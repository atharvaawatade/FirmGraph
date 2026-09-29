"""Deterministic ranking: the answer to the 92%-false-positive firehose.

Tiers (each finding gets exactly one, with the reason stated):
  P1  KEV — known exploited in the wild (CISA KEV via the vuln DB)
  P2  EPSS >= 10% — meaningful probability of exploitation
  P3  reachable + critical/high — in the boot path AND severe
      (incl. a critical/high on a network-exposed running service — remote surface)
  P4  critical/high severity
  P5  everything else

Within a tier: EPSS desc, then severity, then finding id — fully deterministic,
same inputs + same DB snapshot => same order, always.
"""

from __future__ import annotations

from firmgraph.models import Finding

EPSS_THRESHOLD = 0.10

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _tier(f: Finding, network_exposed: frozenset[str]) -> tuple[int, str]:
    if f.kev:
        return 1, "known exploited in the wild (KEV)"
    if f.kind != "cve" and f.severity in ("critical", "high"):
        # secrets/config findings are CERTAIN observations, not probabilistic matches
        return 2, f"direct evidence in the filesystem ({f.kind}) — not a probabilistic match"
    if f.epss is not None and f.epss >= EPSS_THRESHOLD:
        return 2, f"EPSS {f.epss:.0%} — high exploitation probability"
    comp = (f.component or "").split("@")[0].strip().lower()
    if comp in network_exposed and f.severity in ("critical", "high"):
        return 3, f"{f.severity} on a network-exposed running service — remote attack surface"
    if f.reachable is True and f.severity in ("critical", "high"):
        return 3, f"{f.severity} and reachable in the boot/exec path"
    if f.severity in ("critical", "high"):
        return 4, f"{f.severity} severity"
    return 5, "lower severity / no exploitation signal"


def rank_findings(
    findings: list[Finding], network_exposed: frozenset[str] = frozenset()
) -> list[Finding]:
    """Return a new list: priorities assigned, sorted deterministically.

    network_exposed: base names of network-facing running services (Rung 4) — a
    critical/high on one of these is promoted as the remote attack surface.
    """
    ranked = [
        f.model_copy(update={"priority": tier, "priority_reason": reason})
        for f, (tier, reason) in ((f, _tier(f, network_exposed)) for f in findings)
    ]
    ranked.sort(
        key=lambda f: (
            f.suppressed,  # suppressed sink to the bottom, never vanish
            f.priority,
            -(f.epss or 0.0),
            _SEVERITY_ORDER.get(f.severity, 9),
            f.finding_id,
            f.component or "",
        )
    )
    return ranked
