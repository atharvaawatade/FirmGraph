"""VEX generation (Builder): our triage as a portable, standards-grounded
exploitability statement.

The sharpest answer to "how is this different from a scanner?": a scanner
gives you 122 CVEs; this emits a VEX document saying which ones matter and
why the rest don't — in the format downstream (importers, customers, notified
bodies) can consume.

Status mapping — deterministic and honest, per the frozen plan:
- suppressed (reason given)      -> not_affected, our reason as impact_statement
  (OpenVEX requires justification OR impact_statement for not_affected; a
  free-text reason is an impact_statement — spec-correct, never shoehorned
  into the 5-value justification enum)
- reachable is False (heuristic) -> under_investigation
  (a heuristic is not proof; we never over-claim not_affected from it)
- everything else                -> affected, with the ranked action statement

Liability discipline: these are DRAFTED assessments. The manufacturer reviews
and signs — stated in the document metadata itself, not just our docs.
"""

from __future__ import annotations

from typing import Any

from firmgraph.models import Finding, ScanManifest

DRAFT_NOTE = (
    "Drafted by FirmGraph from deterministic analysis (reachability heuristic, "
    "suppression rules with reasons). The manufacturer must review and sign; "
    "this document is evidence, not a compliance determination."
)


def vex_status(finding: Finding) -> tuple[str, str]:
    """(status, statement) for one finding. Deterministic; the honesty rules live here."""
    if finding.suppressed:
        return "not_affected", finding.suppression_reason or "suppressed by reviewer"
    if finding.reachable is False:
        return (
            "under_investigation",
            "component not found in boot/exec path by Linux-filesystem heuristic; "
            "heuristic is not proof — verify before asserting not_affected",
        )
    action = finding.priority_reason or "assess and remediate"
    return "affected", f"P{finding.priority}: {action}"


def _product_id(manifest: ScanManifest) -> str:
    return f"firmware:sha256:{manifest.image_sha256}"


# When one CVE appears more than once (multiple components, or two engines),
# VEX must state it ONCE per product with the most conservative verdict:
# if it's exploitable anywhere, the product is affected.
_STATUS_PRIORITY = {"affected": 0, "under_investigation": 1, "not_affected": 2, "fixed": 3}


def _statements_by_vulnerability(findings: list[Finding]) -> list[tuple[str, str, str]]:
    """Collapse findings to one (cve_id, status, statement) per CVE, keeping the
    most conservative status. Deterministic (sorted by cve id)."""
    best: dict[str, tuple[str, str]] = {}
    for finding in findings:
        if finding.kind != "cve":  # VEX speaks about CVEs, not config/secret rules
            continue
        status, statement = vex_status(finding)
        current = best.get(finding.finding_id)
        if current is None or _STATUS_PRIORITY[status] < _STATUS_PRIORITY[current[0]]:
            best[finding.finding_id] = (status, statement)
    return [(cve, s[0], s[1]) for cve, s in sorted(best.items())]


def build_openvex(manifest: ScanManifest, findings: list[Finding]) -> dict[str, Any]:
    """OpenVEX document: @context/@id/author/timestamp/statements[]."""
    statements: list[dict[str, Any]] = []
    for finding_id, status, statement in _statements_by_vulnerability(findings):
        entry: dict[str, Any] = {
            "vulnerability": {"name": finding_id},
            "products": [{"@id": _product_id(manifest)}],
            "status": status,
        }
        if status == "not_affected":
            entry["impact_statement"] = statement
        else:
            entry["action_statement" if status == "affected" else "status_notes"] = statement
        statements.append(entry)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://firmgraph.dev/vex/{manifest.scan_id}",
        "author": f"FirmGraph {manifest.firmgraph_version} (draft — manufacturer signs)",
        "timestamp": manifest.created_at,
        "version": 1,
        "tooling": f"firmgraph/{manifest.firmgraph_version}",
        "notes": DRAFT_NOTE,
        "statements": statements,
    }


_CDX_STATE = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "under_investigation": "in_triage",
}


def build_cyclonedx_vex(manifest: ScanManifest, findings: list[Finding]) -> dict[str, Any]:
    """CycloneDX 1.5 VEX: vulnerabilities[] with analysis.state + detail."""
    vulnerabilities: list[dict[str, Any]] = []
    for finding_id, status, statement in _statements_by_vulnerability(findings):
        vulnerabilities.append(
            {
                "id": finding_id,
                "analysis": {
                    "state": _CDX_STATE[status],
                    "detail": statement,
                },
                "affects": [{"ref": _product_id(manifest)}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": manifest.created_at,
            "tools": [{"vendor": "FirmGraph", "name": "firmgraph",
                       "version": manifest.firmgraph_version}],
            "properties": [{"name": "firmgraph:draft-note", "value": DRAFT_NOTE}],
        },
        "vulnerabilities": vulnerabilities,
    }
