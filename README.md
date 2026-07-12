# FirmGraph

**The open evidence layer for firmware.** One command: firmware image in → reproducible security graph, prioritized findings, and audit-ready evidence out. Fully local — your firmware never leaves your machine.

> **Status (V0.1.0):** the full pipeline works end-to-end — extraction (unblob→binwalk, jailed), SBOM (Syft, provenance + confidence), CVE matching (Grype, **vulnerability DB baked into the image**), KEV/EPSS/reachability **prioritization**, secrets/config **checks**, content-addressed **graph + diff**, **CRA Annex I mapping**, **VEX** (OpenVEX + CycloneDX), the **evidence pack**, and an optional AI **explainer**. Fully air-gapped, zero DB setup. 62 tests, ruff + mypy --strict clean.
>
> 👉 **Full feature + honest-status snapshot: [STATUS.md](STATUS.md)** · limits: [docs/honest-limits.md](docs/honest-limits.md)

## Quickstart — Docker (recommended; CVE matching works air-gapped, no setup)

```bash
docker build -f docker/Dockerfile -t firmgraph .
mkdir -p out
# firmware mounted read-only; --network=none proves nothing phones home
docker run --rm --network=none \
  -v "$PWD/examples:/work:ro" -v "$PWD/out:/out" \
  firmgraph scan /work/demo-firmware.tar -o /out
open out/report.html
```

The image ships a complete offline vulnerability database (it's large on purpose) —
scan any real firmware the same way, fully offline.

## Quickstart — local (no Docker)

```bash
# needs syft + grype on PATH (and a grype DB: `grype db update` once); unblob runs via Docker
uv sync
uv run firmgraph scan examples/demo-firmware.tar -o out
open out/report.html
```

## Commands

| Command | What it does |
|---|---|
| `firmgraph scan <image>` | Full pipeline: ingest → extract → SBOM → detect → enrich → graph → report → export |
| `firmgraph diff <scan_a> <scan_b>` | What changed between two scans — a set operation over content-addressed nodes |
| `firmgraph history` | Recorded scans (the product remembers so you don't) |

## Principles (non-negotiable)

1. **Local-first.** Nothing phones home — enforced by a CI test that runs a full scan under `--network=none`.
2. **Reproducible.** Same image in → identical content-addressed graph out (`tests/test_determinism.py` is the product promise as code).
3. **Honest.** Extraction confidence is surfaced, stub stages label themselves, low-confidence reports carry a warning banner. A clean result on unextracted firmware is a false negative, not a safe device.
4. **We draft, the manufacturer signs.** Every artifact carries the liability line: evidence, not a compliance determination.

## License

Apache-2.0 — and it stays Apache-2.0. See the governance promises in the project docs.
