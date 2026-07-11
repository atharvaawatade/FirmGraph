"""AI explainer (LiteLLM, BYO key) — explainer only, NEVER judge.

Seven reviews drew the same line and it holds here in code:
- the model never decides true/false positive; classification stays
  deterministic (KEV/EPSS/reachability/rules);
- output is labelled advisory and lives outside the graph, so LLM drift can
  never break reproducibility;
- responses are cached on (finding content, model, prompt version) — re-runs
  are stable and auditable;
- circuit breaker: repeated failures stop further calls; the scan always
  completes. No key, no litellm installed, API down => tool fully functional.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from firmgraph.models import Finding

PROMPT_VERSION = "p1"
ADVISORY_LABEL = "AI-drafted, advisory — verify before acting"
_MAX_CONSECUTIVE_FAILURES = 3
_DEFAULT_TIMEOUT_S = 20

_PROMPT_TEMPLATE = """\
You are the explanation layer of a firmware security scanner. You NEVER decide \
whether a finding is a true or false positive; you only explain.

Finding:
- id: {finding_id} ({kind})
- severity: {severity}
- component: {component}
- fix available: {fix}
- known-exploited (KEV): {kev}
- EPSS: {epss}
- reachable in boot/exec path: {reachable}
- detail: {summary}

Write for a firmware engineer with no security background. At most 120 words, \
three labelled parts:
WHY IT MATTERS: the concrete risk on an embedded/network device.
WHAT TO CHECK: 2-3 specific verification steps in their own build (configs, \
compile flags, whether the vulnerable feature is used).
STANDARDS: the CWE most likely implicated; note the CRA Annex I mapping is in \
the report.

Rules: no verdicts ("this is/isn't exploitable"), never say "non-compliant", \
hedge appropriately, plain language."""


def build_prompt(finding: Finding) -> str:
    return _PROMPT_TEMPLATE.format(
        finding_id=finding.finding_id,
        kind=finding.kind,
        severity=finding.severity,
        component=finding.component or "unknown",
        fix=finding.fix or "none (possible EOL component)",
        kev="yes" if finding.kev else "no",
        epss=f"{finding.epss:.0%}" if finding.epss is not None else "n/a",
        reachable={True: "yes", False: "no"}.get(finding.reachable, "n/a"),  # type: ignore[arg-type]
        summary=finding.summary[:300] or "no additional detail",
    )


def cache_key(finding: Finding, model: str) -> str:
    payload = finding.model_dump_json() + "\x00" + model + "\x00" + PROMPT_VERSION
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ExplainCache:
    """File-per-entry cache: auditable, deterministic re-runs, trivially inspectable."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    def get(self, key: str) -> str | None:
        path = self.cache_dir / f"{key}.json"
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            text = entry.get("text")
            return str(text) if text else None
        except (OSError, ValueError):
            return None

    def put(self, key: str, finding_id: str, model: str, text: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "finding_id": finding_id,
            "model": model,
            "prompt_version": PROMPT_VERSION,
            "text": text,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        (self.cache_dir / f"{key}.json").write_text(
            json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8"
        )


def default_model() -> str | None:
    """BYO key: infer a model from whichever key is present. Override with FIRMGRAPH_LLM_MODEL."""
    explicit = os.environ.get("FIRMGRAPH_LLM_MODEL")
    if explicit:
        return explicit
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini/gemini-2.0-flash"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic/claude-sonnet-4-5"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai/gpt-4o-mini"
    return None


def default_cache_dir() -> Path:
    return Path.home() / ".firmgraph" / "ai-cache"


class LiteLLMExplainer:
    name = "litellm"

    def __init__(
        self,
        model: str,
        cache_dir: Path | None = None,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
    ) -> None:
        self.model = model
        self.cache = ExplainCache(cache_dir or default_cache_dir())
        self.timeout_s = timeout_s
        self._consecutive_failures = 0

    def available(self) -> bool:
        try:
            importlib.import_module("litellm")
        except ImportError:
            return False
        return default_model() is not None

    def explain(self, finding: Finding) -> str | None:
        if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            return None  # circuit open: the scan always completes
        key = cache_key(finding, self.model)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        text = self._call(finding)
        if text is None:
            self._consecutive_failures += 1
            return None
        self._consecutive_failures = 0
        self.cache.put(key, finding.finding_id, self.model, text)
        return text

    def _call(self, finding: Finding) -> str | None:
        try:
            litellm: Any = importlib.import_module("litellm")
            response = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": build_prompt(finding)}],
                timeout=self.timeout_s,
                max_tokens=400,
            )
            content = response.choices[0].message.content
            return str(content).strip() if content else None
        except Exception:  # any failure is a soft failure — advisory layer only
            return None
