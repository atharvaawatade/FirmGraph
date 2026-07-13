# FirmGraph

**The open evidence layer for firmware.** One local command turns a firmware image into a
reproducible security graph, prioritized findings, a CRA-mapped evidence pack, and a VEX
document. Your firmware never leaves the machine.

FirmGraph does **not** reinvent scanning — it orchestrates the best open-source firmware tools
(unblob, Syft, Grype) and adds the layer they don't have: **de-duplication, prioritization,
honest confidence, reproducibility, a diff between releases, CRA Annex I mapping, and a signed-off
evidence pack.** Scanning is commoditized; trustworthy evidence is the point.

> **This README is written to be verifiable, not aspirational.** Every claim below maps to a stage,
> a tool, or a test. The [Honest limitations](#honest-limitations-read-this) section is not
> boilerplate — read it.

---

## What it is / what it is not

| It IS | It is NOT |
|---|---|
| An orchestration + evidence layer over unblob/Syft/Grype | A new vulnerability scanner or a new CVE database |
| Version-match CVE detection + secrets/config rules | A source-code SAST tool or a fuzzer |
| A reproducibility + prioritization + reporting engine | A compliance *determination* — "we draft, you sign" |
| Fully local / air-gapped, deterministic | A magic false-positive eliminator (it *manages* noise, honestly) |

---

## The pipeline — every stage, the real tool, what actually happens

`firmgraph scan <image>` runs **11 stages** in sequence (`firmgraph/scanner.py`). Each stage is a
Template-Method class (`firmgraph/stages/`) that records its own provenance into the scan manifest.
Data flows through a mutable `ScanContext`. Determinism comes from content-addressing + pinned
tools, not from executor cleverness.

```
 image
   │
 [1] ingest    SHA-256 + format sniff (magic bytes) → stable scan id
   │
 [2] extract   unblob (primary) → binwalk (fallback), inside a security JAIL
   │           → confidence = unblob's chunk-identification ratio (surfaced, never hidden)
   │
 [3] sbom      Syft catalogs components (pkg-DB + binary signatures) → dedup by identity
   │           → CycloneDX + SPDX + syft-json written
   │
 [4] detect    Grype matches SBOM → CVEs (baked offline DB); KEV + EPSS ride in;
   │           EOL "no fix available" preserved as first-class evidence
   │
 [4a] binscan  cve-bin-tool second engine (binary signatures) — SEE LIMITS: currently
   │           crashes upstream → gracefully skipped, 0 findings, never a failure
   │
 [5] checks    YAML rulepack: hardcoded keys / telnet-on / root-login / world-writable
   │           → secrets REDACTED by default (sha256 prefix only)
   │
 [6] enrich    dedup findings → reachability heuristic → suppression → deterministic ranking
   │           (KEV > EPSS≥10% > reachable+severe > severe > rest), each with a stated reason
   │
 [6a] explain  optional LiteLLM AI explainer — off without a key, NEVER decides true/false-positive
   │
 [7] graph     content-addressed nodes/edges in SQLite (node id = hash of canonical content)
   │
 [8] report    HTML + Markdown: exec summary, per-component grouping, top-N cap,
   │           CRA Annex I table, VEX summary
   │
 [9] export    CycloneDX/SPDX/graph.json + evidence-pack/ (manifest, findings, cra-mapping,
                VEX ×2, README)
```

### [1] ingest — identity
SHA-256 of the whole image, size, and format detection by magic bytes (squashfs `hsqs`, gzip,
xz, ubi, uImage…). Produces a stable `scan_id` = `sha256[:12]-timestamp`. This is the anchor for
history and diff.

### [2] extract — the hardest 20%, jailed
Firmware is **hostile input**, so extraction runs behind adapters and a security jail
(`firmgraph/security/jail.py`):
- **Engine chain** (`firmgraph/adapters/`): `unblob` native (in the Docker image) → `unblob` via
  Docker (on dev hosts) → `binwalk` fallback. First engine to produce files wins; every attempt
  is recorded.
- **Jail**: path-traversal guard, symlink-escape removal (a crafted `etc → /etc` can't make us
  walk the host), decompression-bomb budgets (file count / bytes / depth), per-stage timeouts.
- **Confidence** = unblob's own chunk-identification ratio. A 1%-extracted encrypted image is
  reported as **1% confidence with a red banner**, never as a clean "0 findings."
- unblob writes `unblob.log` to its CWD → we run it from a writable dir so a **read-only** firmware
  mount (which we recommend) never crashes it (`tests/test_unblob_adapter.py`).

### [3] sbom — what's inside, with provenance
`Syft` (`firmgraph/adapters/syft.py`) catalogs components from **package databases** (dpkg, apk,
rpm, portage…) and **binary classifiers**. Each component carries:
- **provenance** (which cataloger/signal found it) and a **confidence**: 0.9 package-DB-backed,
  0.6 binary-classified, 0.7 other.
- We **de-duplicate** by `(name, version, type)` — overlay filesystems (OpenWrt's `/rom`) expose
  the package DB twice, so scanners naïvely list every package twice. We don't.
- Exports: CycloneDX 1.x, SPDX 2.3, syft-json (the last is what Grype consumes).

### [4] detect — CVE matching
`Grype` (`firmgraph/adapters/grype.py`) matches the SBOM against a **vulnerability DB baked into
the Docker image** (`/opt/grype/db`). This is how "works air-gapped, zero setup" is *true* — you
can't be offline and download a 1.7 GB DB.
- **KEV** (CISA Known-Exploited) and **EPSS** (exploitation probability) ride in on the same DB —
  one snapshot, one date recorded in the manifest, no second feed to reconcile.
- `GRYPE_DB_AUTO_UPDATE=false` for determinism; `GRYPE_DB_VALIDATE_AGE=false` so the pinned DB
  keeps working past grype's 5-day staleness cutoff (offline for real, not a fuse).
- **EOL evidence**: a CVE with no fixed version is kept as *"no fix available (EOL evidence)"* and
  mapped to CRA II.8 — something a raw CVE list never says.

### [4a] binscan — the second engine (honest status: not producing findings)
`cve-bin-tool` (`firmgraph/adapters/cve_bin_tool.py`) is wired as a **separate** engine that
fingerprints components in stripped binaries Syft can't name — shown in its own report section,
**never merged** with Grype (two engines disagree with no ground truth). **The pinned version
(3.4) has an upstream scan-time crash**, so today it produces **0 findings** and is reported as a
clean *"skipped (unhealthy)"* — never a failure. Enabling it is a tracked V0.2 item.

### [5] checks — what CVE scanners miss
A YAML rulepack (`firmgraph/checks/rulepacks/v1.yaml`) over the extracted filesystem: hardcoded
private keys, root password hashes, AWS keys, telnet-at-boot, `PermitRootLogin yes`,
`PermitEmptyPasswords`, world-writable `/etc`. **Deliberately conservative** (high-confidence
rules only) and **redaction-by-default** — a discovered secret's value never enters a finding,
only its location + a sha256 prefix. Binaries are never content-scanned.

### [6] enrich — turning the firehose into a short list
1. **Dedup** findings by `(cve, component, kind, source)`.
2. **Reachability** (`firmgraph/enrich/reachability.py`): a **Linux-filesystem heuristic** — is the
   component's binary in a PATH dir, its lib in a lib dir, or referenced in an init/systemd file?
   Labeled as a heuristic; **NOT APPLICABLE** (silent) on RTOS/monolithic images.
3. **Suppression** (`firmgraph/triage/`): shareable YAML rules; marking a false positive is
   remembered locally and captured as a TP/FP label (never transmitted).
4. **Ranking** (`firmgraph/enrich/ranking.py`), deterministic tiers each with a reason:
   `P1 KEV > P2 EPSS≥10% or direct-evidence > P3 reachable+severe > P4 severe > P5 rest`.

### [6a] explain — optional AI, explainer never judge
`LiteLLM` (`firmgraph/triage/explainer.py`), BYO key. It writes plain-English "why it matters /
what to check" — it **never** decides true/false-positive (that stays deterministic). Output is
advisory-labeled, cached, and lives **outside** the graph so model drift can't affect
reproducibility. Off by default; ships only after a human-scored 50-finding gate.

### [7] graph — content-addressed, diffable
Every node's id = SHA-256 of its canonicalized content (`firmgraph/graph/`), stored in SQLite.
Two scans of identical content → identical ids → `diff` is a set operation and reproducibility is
testable (`tests/test_determinism.py`). `firmgraph diff v1 v2` reports component version changes,
CVEs resolved/introduced — and **warns if the vuln-DB snapshot differs** so a DB update isn't
misread as a firmware regression.

### [8] report — readable at enterprise scale
HTML + Markdown, deterministic ordering:
- **Executive summary**: components, findings by severity, act-now (P1–P3) vs backlog, KEV count,
  no-fix count.
- **Findings by component**: the kernel's thousands of CVEs collapse to **one row with a ⚠
  version-match flag** instead of 3000 rows.
- **Flat findings capped at 100** by priority; the complete unabridged list is always in
  `evidence-pack/findings.json`.
- **CRA Annex I table** (`firmgraph/cra/`) — rule-based, best-effort, "not legal advice."
- **VEX summary** — affected / not_affected / under_investigation counts.

### [9] export — the evidence pack
`evidence-pack/`: `manifest.json` (the reproducibility receipt — tool versions, DB snapshot date,
per-stage provenance), `findings.json` (complete record), `cra-mapping.json`, **`vex.openvex.json`
+ `vex.cdx.json`** (OpenVEX + CycloneDX VEX — suppressed→not_affected with your reason,
unreachable→under_investigation, rest→affected, deduped per CVE, "manufacturer signs" in
metadata), plus the SBOMs and `graph.json`.

---

## Tools we use (exact, pinned)

| Tool | Version | Role | License |
|---|---|---|---|
| [unblob](https://github.com/onekey-sec/unblob) | 26.6.4 | Firmware extraction (primary) | MIT |
| binwalk | 3.x | Extraction fallback | MIT |
| [Syft](https://github.com/anchore/syft) | 1.46.0 | SBOM / component discovery | Apache-2.0 |
| [Grype](https://github.com/anchore/grype) | 0.115.0 | CVE matching + baked vuln DB | Apache-2.0 |
| [cve-bin-tool](https://github.com/intel/cve-bin-tool) | 3.4 | Binary-signature engine (**broken upstream — skipped**) | GPL-3.0 |
| LiteLLM | ≥1.40 | Optional AI explainer (BYO key) | MIT |
| CISA KEV + FIRST EPSS | via Grype DB | Exploitability signal | — |

Runtime: Python 3.12+ (3.14 in the image), Typer+Rich (CLI), pydantic v2 (typed boundaries),
SQLite (graph), Jinja2 (reports). Base image: `ghcr.io/onekey-sec/unblob` (extractor deps
included). **Image size ≈ 3.2 GB** — on purpose: it ships a complete offline vulnerability DB.

---

## Architecture

- **Pipes & Filters** — 11 sequential stages, each recording provenance.
- **Ports & Adapters (Hexagonal)** — every external tool sits behind a typed port
  (`firmgraph/ports/`). Swapping unblob→EMBA, Syft→X, or Grype→Y is one adapter file + one
  registration line. Broken tools degrade gracefully (see cve-bin-tool).
- **Content-addressed graph** — reproducibility + diff for free.
- **Provenance manifest** — tool versions + DB snapshot dates in every scan = the audit receipt.
- **Security-first** — firmware treated as hostile input; extraction jail; non-root container;
  air-gapped by default.

---

## Honest limitations (read this)

FirmGraph is deliberately transparent — this is the credibility, not a disclaimer.

1. **cve-bin-tool (second engine) produces 0 findings** — v3.4 crashes upstream; we handle it as a
   clean skip. Real second-engine coverage is a tracked V0.2 item.
2. **Kernel / version-match floods** — matching `linux-kernel@6.6.73` pulls in **thousands** of
   CVEs, most for drivers not compiled into the image. V1 can't rule them out per-CVE (no
   kernel-config analysis). We **group + prioritize + cap** them and say so. Read a big kernel
   count as "this version has N known CVEs," not "N things to fix."
3. **SBOM binary identification is partial** — Syft names components with package metadata or known
   binary signatures; unidentified stripped binaries are a **false-negative surface** we don't hide.
4. **Reachability is a crude heuristic** — Linux-filesystem only; misses `dlopen`/proprietary
   launchers; not applicable to RTOS/monolithic images.
5. **checks rulepack v1 is small** — a handful of high-confidence rules; zero findings on a clean
   image is intended, not thoroughness.
6. **CRA mapping is best-effort, rule-based** — harmonized standards aren't final; it's evidence
   organization, **not legal advice**, and needs a compliance-professional review before launch.
7. **AI explainer** is optional, off by default, and unproven until its 50-finding gate passes.
8. **The image is ~3.2 GB** (offline DB). That's the honest cost of a real air-gapped promise.

Full detail: [docs/honest-limits.md](docs/honest-limits.md) · status: [STATUS.md](STATUS.md) ·
the release audit that found real bugs: [AUDIT.md](AUDIT.md).

---

## Determinism & privacy (how they're enforced, not just claimed)

- **Reproducible**: same image + same tool versions + same DB snapshot → identical content-addressed
  graph. `tests/test_determinism.py` is the promise as code (green in CI on every commit).
- **Local-first**: a CI test runs a full scan under `--network=none` and asserts it succeeds. The
  open tool sends nothing anywhere; suppression labels are captured locally only.
- **Honest**: low extraction confidence → red banner; a broken engine → labeled skip; every
  artifact carries the liability line.

---

## Quickstart

**Docker (recommended — CVE matching works air-gapped, zero DB setup):**
```bash
docker build -f docker/Dockerfile -t firmgraph .        # release image (~3.2GB, ships the DB)
mkdir -p out
docker run --rm --network=none \
  -v "$PWD/examples:/work:ro" -v "$PWD/out:/out" \
  firmgraph scan /work/demo-firmware.tar -o /out         # bundled example → real checks findings
open out/report.html
# scan any real firmware the same way, fully offline:
#   -v "$PWD:/work:ro"  firmgraph scan /work/firmware.bin -o /out
```

**Local (no Docker):** needs `syft` + `grype` on PATH (`grype db update` once); unblob runs via
Docker.
```bash
uv sync
uv run firmgraph scan examples/demo-firmware.tar -o out
open out/report.html
```

## Commands

| Command | What it does |
|---|---|
| `firmgraph scan <image>` | The 11-stage pipeline → graph + reports + evidence pack |
| `firmgraph diff <a> <b>` | Semantic release-over-release diff (with DB-drift caveat) |
| `firmgraph history` | Recorded scans |
| `firmgraph suppress <cve> --reason ...` | False-positive rule (shareable YAML) + local label |
| `firmgraph explain-gate <findings.json>` | Human-scored AI-explainer gate (BYO key) |

## Development

```bash
uv sync --dev
uv run pytest -q            # 67 tests incl. determinism + air-gap + report-scale
uv run ruff check firmgraph tests
uv run mypy firmgraph       # strict
```

## License

Apache-2.0 — and it stays Apache-2.0 (a public pledge; see `docs/governance.md`). The code is
everyone's; the "FirmGraph" name is ours.
