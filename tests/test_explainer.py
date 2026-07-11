"""Phase-8 guarantees as tests: explainer never touches the graph, degrades to
nothing gracefully, caches deterministically, and is bounded to top findings."""

from __future__ import annotations

import random
from pathlib import Path

from firmgraph.adapters import StubExtractor, StubSbomEngine
from firmgraph.graph.repository import GraphRepository
from firmgraph.models import Component, Finding
from firmgraph.scanner import Scanner
from firmgraph.triage.explainer import (
    PROMPT_VERSION,
    ExplainCache,
    build_prompt,
    cache_key,
)


class FakeExplainer:
    name = "fake-llm"
    model = "fake/model-1"

    def __init__(self, text: str = "WHY IT MATTERS: test.") -> None:
        self.text = text
        self.calls = 0

    def explain(self, finding: Finding) -> str | None:
        self.calls += 1
        return self.text


class SeededMatcher:
    name = "stub-seeded"

    def available(self) -> bool:
        return True

    def findings(self, sbom_path: Path | None, components: list[Component]) -> list[Finding]:
        return [
            Finding(finding_id=f"CVE-2099-{i:04d}", kind="cve", severity="critical",
                    epss=0.5, fix=None)
            for i in range(15)
        ]


def _scan(tmp_path: Path, explainer: FakeExplainer) -> tuple[Path, set[str]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    image = tmp_path / "demo.bin"
    rng = random.Random(11)
    image.write_bytes(bytes(rng.getrandbits(8) for _ in range(2048)))
    out = tmp_path / f"out-{explainer.text[:8]}"
    db = tmp_path / f"g-{len(explainer.text)}.db"
    result = Scanner(
        db_path=db,
        extractor=StubExtractor(),
        sbom_engine=StubSbomEngine(),
        matcher=SeededMatcher(),
        suppressions_path=tmp_path / "none.yaml",
        explainer=explainer,
    ).scan(image, out_dir=out, quiet=True)
    repo = GraphRepository(db)
    try:
        nodes = repo.node_ids(result.manifest.scan_id)
    finally:
        repo.close()
    return out, nodes


def test_explanations_never_enter_the_graph(tmp_path: Path) -> None:
    """LLM drift must be structurally unable to break determinism."""
    _, nodes_a = _scan(tmp_path / "a", FakeExplainer("explanation ONE"))
    _, nodes_b = _scan(tmp_path / "b", FakeExplainer("totally different TWO"))
    assert nodes_a == nodes_b, "different AI output must yield identical graph node ids"


def test_explanations_rendered_with_advisory_label(tmp_path: Path) -> None:
    out, _ = _scan(tmp_path, FakeExplainer("WHY IT MATTERS: because tests."))
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "AI-drafted, advisory" in md
    assert "because tests." in md


def test_explainer_bounded_to_top_findings(tmp_path: Path) -> None:
    fake = FakeExplainer()
    _scan(tmp_path, fake)
    assert fake.calls == 10, "cost-bounded: only the top 10 priority findings"


def test_prompt_contains_no_verdict_language() -> None:
    finding = Finding(finding_id="CVE-1", kind="cve", severity="high", epss=0.9)
    prompt = build_prompt(finding)
    assert "NEVER decide" in prompt
    assert "no verdicts" in prompt
    assert "CVE-1" in prompt and "90%" in prompt


def test_cache_roundtrip_and_key_versioning(tmp_path: Path) -> None:
    finding = Finding(finding_id="CVE-1", kind="cve", severity="high")
    key_a = cache_key(finding, "model-a")
    key_b = cache_key(finding, "model-b")
    assert key_a != key_b, "cache key must include the model"
    assert PROMPT_VERSION in ("p1",), "bump test when prompt version changes"

    cache = ExplainCache(tmp_path / "cache")
    assert cache.get(key_a) is None
    cache.put(key_a, "CVE-1", "model-a", "cached text")
    assert cache.get(key_a) == "cached text"
    assert cache.get(key_b) is None
