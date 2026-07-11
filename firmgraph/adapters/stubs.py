"""Walking-skeleton adapters: pass-through implementations that are honest about it.

Every stub says so in its output. No silent failures, no fake data — the
Dahua lesson: a green checkmark on missing data is a lie.
"""

from __future__ import annotations

from pathlib import Path

from firmgraph.models import Component, ExtractionSummary, Finding


class StubExtractor:
    name = "stub-extractor"

    def available(self) -> bool:
        return True

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        dest.mkdir(parents=True, exist_ok=True)
        return ExtractionSummary(
            method=self.name,
            confidence=0.0,
            files_extracted=0,
            notes=("STUB: no real extraction performed (Phase 2 wires unblob/binwalk)",),
        )


class StubSbomEngine:
    name = "stub-sbom"

    def available(self) -> bool:
        return True

    def components(self, extracted_root: Path) -> list[Component]:
        return []


class StubVulnMatcher:
    name = "stub-vuln"

    def available(self) -> bool:
        return True

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]:
        return []


class NullBinaryScanner:
    """Null Object: cve-bin-tool absence is a code path, not an error path.

    The tool is fully functional without it — Syft+Grype still run.
    """

    name = "null-binary-scanner"

    def available(self) -> bool:
        return False

    def scan(self, extracted_root: Path) -> list[Finding]:
        return []


class NullExplainer:
    """Null Object: AI absence is a code path, not an error path."""

    name = "null-explainer"

    def explain(self, finding: Finding) -> str | None:
        return None
