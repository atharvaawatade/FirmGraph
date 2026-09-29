"""ExtractorChain behavior: fallback order, honest attempt trail, graceful zero."""

from __future__ import annotations

from pathlib import Path

from firmgraph.adapters.chain import ExtractorChain
from firmgraph.models import ExtractionSummary


class FakeEngine:
    def __init__(self, name: str, files: int, up: bool = True, confidence: float = 0.9) -> None:
        self.name = name
        self._files = files
        self._up = up
        self._confidence = confidence

    def available(self) -> bool:
        return self._up

    def extract(self, image: Path, dest: Path) -> ExtractionSummary:
        dest.mkdir(parents=True, exist_ok=True)
        return ExtractionSummary(
            method=self.name,
            confidence=self._confidence,
            files_extracted=self._files,
            notes=(),
        )


def test_first_engine_with_files_wins(tmp_path: Path) -> None:
    chain = ExtractorChain([FakeEngine("primary", 100), FakeEngine("fallback", 5)])
    summary = chain.extract(tmp_path / "img.bin", tmp_path / "out")
    assert summary.method == "primary"
    assert summary.files_extracted == 100


def test_falls_back_when_primary_unavailable(tmp_path: Path) -> None:
    chain = ExtractorChain([FakeEngine("primary", 100, up=False), FakeEngine("fallback", 5)])
    summary = chain.extract(tmp_path / "img.bin", tmp_path / "out")
    assert summary.method == "fallback"
    assert "primary: not available" in " ".join(summary.notes)


def test_falls_back_when_primary_extracts_nothing(tmp_path: Path) -> None:
    chain = ExtractorChain([FakeEngine("primary", 0, confidence=0.0), FakeEngine("fallback", 7)])
    summary = chain.extract(tmp_path / "img.bin", tmp_path / "out")
    assert summary.method == "fallback"
    assert summary.files_extracted == 7


def test_graceful_zero_when_nothing_available(tmp_path: Path) -> None:
    chain = ExtractorChain([FakeEngine("a", 9, up=False), FakeEngine("b", 9, up=False)])
    summary = chain.extract(tmp_path / "img.bin", tmp_path / "out")
    assert summary.method == "none"
    assert summary.confidence == 0.0
    assert summary.files_extracted == 0
