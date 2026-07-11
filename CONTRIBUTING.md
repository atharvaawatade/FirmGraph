# Contributing to FirmGraph

Thanks for being here. FirmGraph is the open evidence layer for firmware — and the
fastest ways to make it better are exactly the ones that need people like you.

## The three highest-value contributions

1. **Firmware that breaks us.** Found an image that extracts badly, produces a wrong SBOM, or
   fools a check? Open an issue with the device name and (if public) a download link. Every such
   image makes the [corpus benchmark](docs/corpus-benchmark.md) more honest.
2. **Suppression rules with reasons.** If you've marked findings false-positive for a common
   device class, your `suppressions.yaml` (with the *why*) helps everyone. PR it under
   `rulepacks/community/`.
3. **Check rules.** One YAML block in `firmgraph/checks/rulepacks/` + one seeded test. Keep them
   conservative — we ship signals, not noise. Zero false positives on the clean-tree test is the bar.

## Ground rules

- **DCO**: sign off commits (`git commit -s`). Apache-2.0; you keep your copyright.
- **Determinism is sacred**: if your change makes two scans of the same image differ, it will not
  merge. `tests/test_determinism.py` is the acid test.
- **Honesty over polish**: anything that hides a failure (silent except, fake confidence, green
  checkmark on missing data) will not merge, even if it demos better.
- **The cut list stays cut**: dashboard, REST API, multi-engine SBOM merging — see the project
  docs before proposing them back.

## Dev setup

```bash
git clone <repo> && cd firmgraph
uv sync --dev
uv run pytest -q            # sub-second suite
uv run ruff check firmgraph tests
uv run mypy firmgraph       # strict
```

Adding a tool adapter? One file in `firmgraph/adapters/` implementing a port from
`firmgraph/ports/`, one registration line in `scanner.py`, tests with canned fixtures
(see `tests/test_parsers.py`). That's the Modularity Contract — if a swap takes more than that,
the seam is broken and the fix is the seam, not your code.

## Architecture in one breath

`firmgraph scan` runs a sequential pipeline of stages (`firmgraph/stages/`). Each stage is a
Template-Method class that records its own provenance. External tools live behind **ports**
(`firmgraph/ports/`) with **adapters** (`firmgraph/adapters/`). The graph is content-addressed in
SQLite (`firmgraph/graph/`), which is what makes `diff` and reproducibility work. Read
`docs/honest-limits.md` before you touch anything — it's the soul of the project.
