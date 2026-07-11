"""Evidence-pack scaffold tests: files exist, suppressed included, seams honest."""

from __future__ import annotations

import json
import random
from pathlib import Path

from firmgraph.adapters import StubExtractor, StubSbomEngine
from firmgraph.models import Component, Finding
from firmgraph.report.renderer import LIABILITY_LINE
from firmgraph.scanner import Scanner


class SeededMatcher:
    """Stub matcher that emits one CVE + relies on suppression for the second."""

    name = "stub-seeded"

    def available(self) -> bool:
        return True

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]:
        return [
            Finding(finding_id="CVE-2099-0001", kind="cve", severity="critical", fix=None),
            Finding(finding_id="CVE-2099-0002", kind="cve", severity="low", fix="2.0"),
        ]


def test_evidence_pack_written(tmp_path: Path) -> None:
    image = tmp_path / "demo.bin"
    rng = random.Random(3)
    image.write_bytes(bytes(rng.getrandbits(8) for _ in range(2048)))
    out = tmp_path / "out"

    Scanner(
        db_path=tmp_path / "g.db",
        extractor=StubExtractor(),
        sbom_engine=StubSbomEngine(),
        matcher=SeededMatcher(),
        suppressions_path=tmp_path / "none.yaml",
    ).scan(image, out_dir=out, quiet=True)

    pack = out / "evidence-pack"
    for name in ("manifest.json", "findings.json", "cra-mapping.json", "README.md"):
        assert (pack / name).is_file(), f"missing {name}"

    findings = json.loads((pack / "findings.json").read_text(encoding="utf-8"))
    assert {f["finding_id"] for f in findings} == {"CVE-2099-0001", "CVE-2099-0002"}
    assert all("priority" in f and "priority_reason" in f for f in findings)

    cra = json.loads((pack / "cra-mapping.json").read_text(encoding="utf-8"))
    assert "not legal advice" in cra["disclaimer"].lower()
    reqs = {m["requirement"] for m in cra["mapping"]}
    assert {"I.2a", "II.2", "II.8"} <= reqs, "EOL cve must implicate II.8"

    readme = (pack / "README.md").read_text(encoding="utf-8")
    assert LIABILITY_LINE in readme
    assert "signed by you" in readme, "the manufacturer-signs seam must be explicit"
    assert "Declaration of Conformity" in readme

    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["image_sha256"]
    assert [s["name"] for s in manifest["stages"]]


def test_report_carries_cra_table(tmp_path: Path) -> None:
    image = tmp_path / "demo.bin"
    image.write_bytes(b"\x00" * 512)
    out = tmp_path / "out"
    Scanner(
        db_path=tmp_path / "g.db",
        extractor=StubExtractor(),
        sbom_engine=StubSbomEngine(),
        matcher=SeededMatcher(),
        suppressions_path=tmp_path / "none.yaml",
    ).scan(image, out_dir=out, quiet=True)

    html = (out / "report.html").read_text(encoding="utf-8")
    md = (out / "report.md").read_text(encoding="utf-8")
    for blob in (html, md):
        assert "CRA Annex I mapping (best-effort" in blob
        assert "I.2a" in blob
        # VEX must be VISIBLE in the report, not only in evidence-pack JSON
        assert "Exploitability statement (VEX)" in blob
        assert "you sign" in blob
