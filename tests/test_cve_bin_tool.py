"""Phase-10 tests: cve-bin-tool parser (offline fixture), dedupe-within-engine,
never-merge separation, and graceful absence."""

from __future__ import annotations

from pathlib import Path

from firmgraph.adapters.cve_bin_tool import (
    _first_error_line,
    _looks_like_crash,
    parse_cve_bin_tool_document,
)
from firmgraph.adapters.stubs import NullBinaryScanner
from firmgraph.models import Finding
from firmgraph.pipeline.context import ScanContext
from firmgraph.ports import BinaryScannerUnhealthy
from firmgraph.stages import BinScanStage

CVE_BIN_TOOL_DOC = [
    {
        "vendor": "gnu",
        "product": "glibc",
        "version": "2.19",
        "cve_number": "CVE-2015-0235",
        "severity": "CRITICAL",
        "paths": "/fw/lib/libc.so.6",
    },
    {  # same CVE, same component, different path -> deduped within engine
        "vendor": "gnu",
        "product": "glibc",
        "version": "2.19",
        "cve_number": "CVE-2015-0235",
        "severity": "CRITICAL",
        "paths": "/fw/lib32/libc.so.6",
    },
    {
        "vendor": "openssl",
        "product": "openssl",
        "version": "1.0.2u",
        "cve_number": "CVE-2022-2068",
        "severity": "High",
        "fixed_versions": "3.0.4",
        "paths": "/fw/usr/lib/libcrypto.so",
    },
    {"product": "junk", "version": "1", "cve_number": "UNKNOWN"},  # dropped
]


def test_parser_fixture_and_dedupe() -> None:
    findings = parse_cve_bin_tool_document(CVE_BIN_TOOL_DOC)
    assert len(findings) == 2, "duplicate (cve, component) rows must collapse; UNKNOWN dropped"
    by_id = {f.finding_id: f for f in findings}

    glibc = by_id["CVE-2015-0235"]
    assert glibc.severity == "critical"
    assert glibc.component == "glibc@2.19"
    assert glibc.source == "cve-bin-tool"
    assert glibc.fix is None, "no fixed_versions => EOL evidence preserved"
    assert "libc.so.6" in glibc.summary

    openssl = by_id["CVE-2022-2068"]
    assert openssl.fix == "3.0.4"


def test_findings_stay_separate_from_grype(tmp_path: Path) -> None:
    """The never-merge rule: a grype finding and a cve-bin-tool finding for the
    same CVE coexist, each tagged with its engine."""
    grype_f = Finding(finding_id="CVE-2022-2068", kind="cve", severity="high", source="grype")
    binscan = parse_cve_bin_tool_document(CVE_BIN_TOOL_DOC)
    combined = [grype_f, *binscan]
    same_cve = [f for f in combined if f.finding_id == "CVE-2022-2068"]
    assert len(same_cve) == 2
    assert {f.source for f in same_cve} == {"grype", "cve-bin-tool"}


def test_null_scanner_is_a_clean_code_path(tmp_path: Path) -> None:
    ctx = ScanContext(
        image_path=tmp_path / "x.bin",
        out_dir=tmp_path / "out",
        work_dir=tmp_path,
        db_path=tmp_path / "g.db",
        firmgraph_version="test",
    )
    stage = BinScanStage(NullBinaryScanner())
    stage.run(ctx)
    assert ctx.findings == []
    record = ctx.stage_log[-1]
    assert record.name == "binscan" and record.status == "ok"
    assert "fully functional without it" in " ".join(record.notes)


# -- crash-vs-clean discrimination (the root-cause fix) ---------------------

def test_crash_signatures_detected() -> None:
    # the exact real-world failure we hit with cve-bin-tool 3.4
    crash = "  AttributeError: 'NoneType' object has no attribute 'splitlines'"
    assert _looks_like_crash(crash)
    assert _looks_like_crash("sqlite3.OperationalError: no such table: purl2cpe")
    assert _looks_like_crash("Traceback (most recent call last):")


def test_clean_zero_is_not_a_crash() -> None:
    assert not _looks_like_crash("Scanned 42 files, found 0 known vulnerabilities")
    assert not _looks_like_crash("")


def test_first_error_line_strips_box_noise() -> None:
    boxed = "│    AttributeError: 'NoneType' object has no attribute 'splitlines' │"
    assert _first_error_line(boxed).startswith("AttributeError:")
    assert "│" not in _first_error_line(boxed)


class UnhealthyScanner:
    """A cve-bin-tool that's installed but crashes — the exact V0.1.0 situation."""

    name = "cve-bin-tool"

    def available(self) -> bool:
        return True

    def scan(self, extracted_root: Path) -> list[Finding]:
        raise BinaryScannerUnhealthy("AttributeError: 'NoneType' ... splitlines")


def test_unhealthy_tool_is_a_clean_skip_not_a_failure(tmp_path: Path) -> None:
    """The demo-critical guarantee: a broken bonus engine stays 'ok' + honest,
    never a scary red 'failed' row."""
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    ctx = ScanContext(
        image_path=tmp_path / "x.bin",
        out_dir=tmp_path / "out",
        work_dir=tmp_path,
        db_path=tmp_path / "g.db",
        firmgraph_version="test",
    )
    BinScanStage(UnhealthyScanner()).run(ctx)
    record = ctx.stage_log[-1]
    assert record.status == "ok", "a broken bonus engine must NOT mark the stage failed"
    joined = " ".join(record.notes)
    assert "skipped" in joined and "unhealthy" in joined
    assert "Syft+Grype results stand" in joined
    assert ctx.findings == []
