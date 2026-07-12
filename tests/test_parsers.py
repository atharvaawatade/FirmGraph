"""Offline parser tests: syft-json and grype-json -> our models, no binaries needed."""

from __future__ import annotations

from firmgraph.adapters.grype import parse_grype_document
from firmgraph.adapters.syft import parse_syft_document

SYFT_DOC = {
    "artifacts": [
        {"name": "busybox", "version": "1.19.4", "type": "binary", "foundBy": "binary-classifier-cataloger"},
        {"name": "dnsmasq", "version": "2.93-r1", "type": "apk", "foundBy": "apk-db-cataloger"},
        {"name": "mystery", "version": None, "type": "unknown", "foundBy": "elf-package-cataloger"},
        {"name": "", "version": "1.0"},  # nameless artifacts are dropped
    ],
    "descriptor": {"name": "syft", "version": "1.46.0"},
}

GRYPE_DOC = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2022-2068",
                "severity": "High",
                "description": "The c_rehash script allows command injection.",
                "fix": {"versions": ["1.0.2zf", "3.0.4"], "state": "fixed"},
                "epss": [{"cve": "CVE-2022-2068", "epss": 0.958, "percentile": 0.99}],
                "knownExploited": [{"cve": "CVE-2022-2068"}],
            },
            "artifact": {"name": "openssl", "version": "1.0.2u"},
        },
        {
            "vulnerability": {
                "id": "CVE-2022-48174",
                "severity": "Critical",
                "fix": {"versions": [], "state": "not-fixed"},  # EOL: no fix — first-class evidence
            },
            "artifact": {"name": "busybox", "version": "1.36.1"},
        },
        {"vulnerability": {"id": ""}, "artifact": {}},  # id-less matches are dropped
    ],
    "descriptor": {"db": {"built": "2026-07-05T04:00:00Z"}},
}


def test_syft_parser_provenance_and_confidence() -> None:
    components, version = parse_syft_document(SYFT_DOC)
    assert version == "1.46.0"
    assert len(components) == 3
    by_name = {c.name: c for c in components}
    assert by_name["dnsmasq"].confidence == 0.9  # package-db backed
    assert by_name["busybox"].confidence == 0.6  # binary classified
    assert by_name["busybox"].provenance == "binary-classifier-cataloger"
    assert by_name["mystery"].version is None


def test_grype_v6_db_built_path() -> None:
    """grype v6 moved the DB build date to descriptor.db.status.built — the
    determinism receipt must read it there (regression: was showing 'unknown')."""
    doc = {"matches": [], "descriptor": {"db": {"status": {"built": "2026-07-11T06:57:59Z"}}}}
    _, db_built = parse_grype_document(doc)
    assert db_built == "2026-07-11T06:57:59Z"


def test_grype_parser_findings_kev_epss_and_eol() -> None:
    findings, db_built = parse_grype_document(GRYPE_DOC)
    assert db_built == "2026-07-05T04:00:00Z"  # old-path fallback still works
    assert len(findings) == 2
    by_id = {f.finding_id: f for f in findings}

    openssl = by_id["CVE-2022-2068"]
    assert openssl.severity == "high"
    assert openssl.kev is True
    assert openssl.epss == 0.958
    assert openssl.fix == "1.0.2zf, 3.0.4"
    assert openssl.component == "openssl@1.0.2u"

    eol = by_id["CVE-2022-48174"]
    assert eol.severity == "critical"
    assert eol.fix is None, "no-fix must be preserved: it IS the CRA evidence"
