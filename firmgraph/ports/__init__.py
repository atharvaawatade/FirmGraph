"""Ports (typed interfaces) — the Modularity Contract.

The core imports these, never concrete tools. Swapping unblob for EMBA, Syft for
another engine, or SQLite for Neo4j is a one-file adapter + one registration line.
If it takes more, the seam is broken and we fix the seam, not the caller.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from firmgraph.models import Component, ExtractionSummary, Finding


class Extractor(Protocol):
    """Port for firmware extraction engines (unblob, binwalk, EMBA, plugins)."""

    name: str

    def available(self) -> bool: ...

    def extract(self, image: Path, dest: Path) -> ExtractionSummary: ...


class SbomEngine(Protocol):
    """Port for SBOM/component discovery engines (Syft, ...).

    Convention: engines may write SBOM export documents (syft-json, CycloneDX,
    SPDX) into ``extracted_root.parent / "sbom"`` for downstream stages.
    """

    name: str

    def available(self) -> bool: ...

    def components(self, extracted_root: Path) -> list[Component]: ...


class VulnMatcher(Protocol):
    """Port for vulnerability matchers (Grype, cve-bin-tool, ...)."""

    name: str

    def available(self) -> bool: ...

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]: ...


class BinaryScannerUnhealthy(Exception):
    """A BinaryScanner is installed but not producing usable output (crash,
    broken DB, upstream version defect). Part of the port contract: `scan` may
    raise this to signal a CLEAN SKIP of a bonus engine — not a scan failure.
    Syft+Grype already ran; the report says so honestly without alarming the user.
    """


class BinaryScanner(Protocol):
    """Port for binary-signature vulnerability scanners (cve-bin-tool, ...).

    Distinct from VulnMatcher: it scans the extracted tree directly for
    component signatures in stripped binaries — the executables Syft can't
    name. Its findings are shown SEPARATELY, never merged with the SBOM path
    (frozen decision: no ground truth to reconcile).

    `scan` returns findings, or raises BinaryScannerUnhealthy if the tool is
    present but broken (the stage turns that into a clean, honest skip).
    """

    name: str

    def available(self) -> bool: ...

    def scan(self, extracted_root: Path) -> list[Finding]: ...


class Explainer(Protocol):
    """Port for the AI explainer layer (LiteLLM or NullExplainer).

    Explainer only, never judge: it never decides true/false positive.
    """

    name: str

    def explain(self, finding: Finding) -> str | None: ...
