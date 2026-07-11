# FirmGraph

**The open evidence layer for firmware.** One command: firmware image in → reproducible security graph, prioritized findings, and audit-ready evidence out. Fully local — your firmware never leaves your machine.

> **Status (V0.1.0-dev):** the full pipeline is real and working end-to-end — extraction (unblob→binwalk, jailed), SBOM (Syft, provenance + confidence), CVE matching (Grype, pinned DB), KEV/EPSS/reachability **prioritization**, secrets/config **checks**, content-addressed **graph + diff**, **CRA Annex I mapping**, **VEX** (OpenVEX + CycloneDX), the **evidence pack**, and an optional AI **explainer**. A 15MB router scans in ~14s with 122 findings, fully air-gapped. 61 tests, ruff + mypy --strict clean.
>
> 👉 **Full feature + honest-status snapshot: [STATUS.md](STATUS.md)** · limits: [docs/honest-limits.md](docs/honest-limits.md)

```bash
# the real thing, fully air-gapped:
docker run --rm --entrypoint grype firmgraph -v fg-cache:/home/unblob/.cache db update   # once, online
docker run --rm --network=none -v fg-cache:/home/unblob/.cache -v "$PWD:/work" \
  firmgraph scan /work/firmware.bin -o /work/out
```

## Quickstart

```bash
# local — scans the bundled example firmware (real findings: telnet-on, hardcoded key, root login)
uv sync
uv run firmgraph scan examples/demo-firmware.tar -o out
open out/report.html
# (for a full CVE demo, scan a real image — e.g. an OpenWrt sysupgrade .bin from openwrt.org)

# docker (recommended: air-gapped)
docker build -f docker/Dockerfile -t firmgraph .
docker run --rm --network=none -v "$PWD:/work" firmgraph scan /work/demo.bin -o /work/firmgraph_out
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
