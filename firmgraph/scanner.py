"""Scanner (Facade): the one entry point — CLI today, anything later."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

import firmgraph
from firmgraph.adapters import (
    BinwalkAdapter,
    CveBinToolAdapter,
    ExtractorChain,
    GrypeAdapter,
    NullBinaryScanner,
    SyftAdapter,
    UnblobDockerAdapter,
    UnblobNativeAdapter,
)
from firmgraph.graph.repository import GraphRepository
from firmgraph.models import ScanManifest
from firmgraph.ports import BinaryScanner, Explainer, Extractor, SbomEngine, VulnMatcher
from firmgraph.pipeline.context import ScanContext
from firmgraph.pipeline.executor import SequentialPipeline
from firmgraph.stages import (
    BinScanStage,
    ChecksStage,
    DetectStage,
    EnrichStage,
    ExplainStage,
    ExportStage,
    ExtractStage,
    GraphStage,
    IngestStage,
    ReportStage,
    SbomStage,
)


def default_db_path() -> Path:
    return Path.home() / ".firmgraph" / "firmgraph.db"


def default_extractor() -> ExtractorChain:
    """Extraction strategy order: native unblob (inside our image / Linux) ->
    dockerized unblob (dev hosts) -> binwalk (fallback, confidence-capped)."""
    return ExtractorChain(
        engines=[UnblobNativeAdapter(), UnblobDockerAdapter(), BinwalkAdapter()]
    )


def default_explainer() -> Explainer:
    """LiteLLM when a key + install are present; NullExplainer otherwise.

    AI absence is a code path, not an error path — the tool is fully
    functional without any key (frozen posture: explainer, never judge).
    """
    from firmgraph.adapters import NullExplainer
    from firmgraph.triage.explainer import LiteLLMExplainer, default_model

    model = default_model()
    if model is not None:
        candidate = LiteLLMExplainer(model=model)
        if candidate.available():
            return candidate
    return NullExplainer()


def default_binary_scanner() -> BinaryScanner:
    """cve-bin-tool when installed; NullBinaryScanner otherwise (Syft+Grype still run)."""
    candidate = CveBinToolAdapter()
    return candidate if candidate.available() else NullBinaryScanner()


def build_default_pipeline(
    extractor: Extractor | None = None,
    sbom_engine: SbomEngine | None = None,
    matcher: VulnMatcher | None = None,
    binary_scanner: BinaryScanner | None = None,
    suppressions_path: Path | None = None,
    explainer: Explainer | None = None,
) -> SequentialPipeline:
    """Stage registration — the Modularity Contract's single wiring point."""
    return SequentialPipeline(
        stages=[
            IngestStage(),
            ExtractStage(extractor or default_extractor()),
            SbomStage(sbom_engine or SyftAdapter()),
            DetectStage(matcher or GrypeAdapter()),
            BinScanStage(binary_scanner or default_binary_scanner()),
            ChecksStage(),
            EnrichStage(suppressions_path=suppressions_path),
            ExplainStage(explainer or default_explainer()),
            GraphStage(),
            ReportStage(),
            ExportStage(),
        ]
    )


@dataclass(frozen=True)
class ScanResult:
    manifest: ScanManifest
    report_paths: tuple[Path, ...]
    node_count: int


class Scanner:
    def __init__(
        self,
        db_path: Path | None = None,
        extractor: Extractor | None = None,
        sbom_engine: SbomEngine | None = None,
        matcher: VulnMatcher | None = None,
        binary_scanner: BinaryScanner | None = None,
        suppressions_path: Path | None = None,
        explainer: Explainer | None = None,
    ) -> None:
        self.db_path = db_path or default_db_path()
        self.extractor = extractor
        self.sbom_engine = sbom_engine
        self.matcher = matcher
        self.binary_scanner = binary_scanner
        self.suppressions_path = suppressions_path
        self.explainer = explainer

    def scan(
        self,
        image: Path,
        out_dir: Path,
        console: Console | None = None,
        quiet: bool = False,
    ) -> ScanResult:
        work_dir = Path(tempfile.mkdtemp(prefix="firmgraph-"))
        ctx = ScanContext(
            image_path=image,
            out_dir=out_dir,
            work_dir=work_dir,
            db_path=self.db_path,
            firmgraph_version=firmgraph.__version__,
        )
        pipeline = build_default_pipeline(
            extractor=self.extractor,
            sbom_engine=self.sbom_engine,
            matcher=self.matcher,
            binary_scanner=self.binary_scanner,
            suppressions_path=self.suppressions_path,
            explainer=self.explainer,
        )
        try:
            # ingest must run before the scan row exists (needs the hash) —
            # run stage 1 manually, record the scan, then run the rest.
            pipeline.stages[0].run(ctx)
            repo = GraphRepository(self.db_path)
            try:
                from datetime import datetime, timezone

                repo.record_scan(
                    ctx.scan_id,
                    ctx.image_sha256,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                )
            finally:
                repo.close()
            rest = SequentialPipeline(pipeline.stages[1:])
            manifest = rest.run(ctx, console=console, quiet=quiet)
            # persist the full manifest (audit trail)
            repo = GraphRepository(self.db_path)
            try:
                repo.save_manifest(ctx.scan_id, manifest.model_dump_json())
            finally:
                repo.close()
            return ScanResult(
                manifest=manifest,
                report_paths=tuple(ctx.report_paths),
                node_count=ctx.node_count,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
