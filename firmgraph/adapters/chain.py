"""ExtractorChain (Chain of Responsibility over the Extractor port).

Tries engines in priority order; first one to produce files wins. Every
attempt — including the ones that failed or weren't available — is recorded
in the notes: an auditor should see the whole decision, not just the winner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from firmgraph.models import ExtractionSummary


@runtime_checkable
class ChainableExtractor(Protocol):
    name: str

    def available(self) -> bool: ...

    def extract(self, image: Path, dest: Path) -> ExtractionSummary: ...


class ExtractorChain:
    name = "auto"

    def __init__(self, engines: list[ChainableExtractor]) -> None:
        self.engines = engines

    def available(self) -> bool:
        return any(e.available() for e in self.engines)

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        attempts: list[str] = []
        best: ExtractionSummary | None = None
        for engine in self.engines:
            if not engine.available():
                attempts.append(f"{engine.name}: not available")
                continue
            summary = engine.extract(image, dest / engine.name)
            attempts.append(
                f"{engine.name}: files={summary.files_extracted} "
                f"confidence={summary.confidence:.2f}"
            )
            if best is None or summary.files_extracted > best.files_extracted:
                best = summary
            if summary.files_extracted > 0:
                break  # first engine that produces real bytes wins
        if best is None:
            best = ExtractionSummary(
                method="none",
                confidence=0.0,
                files_extracted=0,
                notes=("no extraction engine available",),
            )
        return ExtractionSummary(
            method=best.method,
            confidence=best.confidence,
            files_extracted=best.files_extracted,
            notes=(*best.notes, "chain: " + " | ".join(attempts)),
        )
