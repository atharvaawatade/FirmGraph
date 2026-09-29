"""Phase-11 VEX tests: status mapping honesty, OpenVEX/CycloneDX structure,
determinism, and the manufacturer-signs metadata."""

from __future__ import annotations

from firmgraph.models import Finding, ScanManifest
from firmgraph.vex import build_cyclonedx_vex, build_openvex, vex_status

MANIFEST = ScanManifest(
    scan_id="abc123-20260707T000000Z",
    firmgraph_version="0.1.0.dev0",
    image_path="/fw/x.bin",
    image_sha256="a" * 64,
    image_size=1024,
    image_format="squashfs",
    created_at="2026-07-07T00:00:00+00:00",
)


def _f(fid: str, **kw: object) -> Finding:
    base: dict[str, object] = {"finding_id": fid, "kind": "cve", "severity": "high"}
    base.update(kw)
    return Finding.model_validate(base)


FINDINGS = [
    _f("CVE-AFFECTED", priority=2, priority_reason="EPSS 96% — high exploitation probability"),
    _f("CVE-SUPPRESSED", suppressed=True, suppression_reason="feature not compiled in"),
    _f("CVE-UNREACHABLE", reachable=False),
    _f("FG-SECRET-001@etc/k", kind="secret"),  # non-CVE: excluded from VEX
]


def test_status_mapping_honesty() -> None:
    assert vex_status(_f("A", suppressed=True, suppression_reason="r"))[0] == "not_affected"
    status, note = vex_status(_f("B", reachable=False))
    assert status == "under_investigation", "a heuristic must never claim not_affected"
    assert "heuristic is not proof" in note
    assert vex_status(_f("C", reachable=True))[0] == "affected"
    assert vex_status(_f("D"))[0] == "affected"  # reachable unknown => affected (conservative)


def test_openvex_structure_and_content() -> None:
    doc = build_openvex(MANIFEST, FINDINGS)
    # spec-required top-level fields
    for key in ("@context", "@id", "author", "timestamp", "version", "statements"):
        assert key in doc, f"OpenVEX missing {key}"
    assert "manufacturer signs" in doc["author"]

    statements = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    assert set(statements) == {"CVE-AFFECTED", "CVE-SUPPRESSED", "CVE-UNREACHABLE"}, (
        "VEX speaks about CVEs only; checks findings excluded"
    )
    supp = statements["CVE-SUPPRESSED"]
    assert supp["status"] == "not_affected"
    assert supp["impact_statement"] == "feature not compiled in", (
        "not_affected MUST carry impact_statement (spec) — our reason travels in it"
    )
    aff = statements["CVE-AFFECTED"]
    assert aff["status"] == "affected"
    assert "EPSS 96%" in aff["action_statement"]
    for s in statements.values():
        assert s["products"][0]["@id"] == f"firmware:sha256:{'a' * 64}"


def test_cyclonedx_structure_and_states() -> None:
    doc = build_cyclonedx_vex(MANIFEST, FINDINGS)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    states = {v["id"]: v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states == {
        "CVE-AFFECTED": "exploitable",
        "CVE-SUPPRESSED": "not_affected",
        "CVE-UNREACHABLE": "in_triage",
    }
    props = doc["metadata"]["properties"]
    assert any("manufacturer must review and sign" in p["value"] for p in props)


def test_determinism() -> None:
    a = build_openvex(MANIFEST, FINDINGS)
    b = build_openvex(MANIFEST, list(reversed(FINDINGS)))
    assert a == b, "same findings in any order => identical VEX document"


def test_same_cve_deduped_to_one_conservative_statement() -> None:
    """One CVE on two components (or from two engines) => a single VEX statement,
    most-conservative status (affected wins over not_affected)."""
    findings = [
        _f("CVE-DUP", component="proftpd@1.0", suppressed=True, suppression_reason="off"),
        _f("CVE-DUP", component="openssl@1.0", priority=2, priority_reason="reachable"),
    ]
    doc = build_openvex(MANIFEST, findings)
    dup = [s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-DUP"]
    assert len(dup) == 1, "VEX must state each CVE once per product"
    assert dup[0]["status"] == "affected", "exploitable-anywhere => product is affected"

    cdx = build_cyclonedx_vex(MANIFEST, findings)
    dup_cdx = [v for v in cdx["vulnerabilities"] if v["id"] == "CVE-DUP"]
    assert len(dup_cdx) == 1 and dup_cdx[0]["analysis"]["state"] == "exploitable"
