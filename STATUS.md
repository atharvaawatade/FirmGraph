# FirmGraph — Status & Feature Snapshot

> **Version:** V0.1.0 · **As of:** July 2026 · under git (initial release commit)
> **One line:** The open evidence layer for firmware — one local command turns a firmware image into a reproducible, prioritized, CRA-mapped evidence pack.
> **Health:** 62 tests passing · ruff clean · mypy --strict clean · 51 modules · Docker image runs fully air-gapped (incl. read-only firmware mounts).
> **Clone-and-run:** bundled `examples/demo-firmware.tar` produces 5 real findings on first scan (verified from a fresh `git archive` clone).
> **Honesty rule:** every row below is marked ✅ working / 🟡 optional-gated / 🔧 tracked. No feature is claimed that isn't real. If this contradicts a slide, this doc wins.

---

## 1. What it does — the pipeline, stage by stage

One command — `firmgraph scan <image>` — runs 10 stages, each recording its own provenance:

| # | Stage | What it does | Status |
|---|---|---|---|
| 1 | **ingest** | SHA-256, format detect, stable scan id | ✅ |
| 2 | **extract** | unblob → binwalk fallback, in a security **jail** (path-traversal / symlink-escape / decompression-bomb guards), honest **confidence score** | ✅ |
| 3 | **sbom** | Syft — components with **provenance + confidence**; CycloneDX + SPDX export | ✅ |
| 4 | **detect** | Grype — CVE matching, **pinned DB snapshot** (determinism), EOL/no-fix surfaced as evidence | ✅ |
| 4a | **binscan** | cve-bin-tool second engine (binary signatures), shown separately, never merged | 🔧 integration done; tool v3.4 crashes → **gracefully skipped**, 0 findings (tracked) |
| 5 | **checks** | secrets / weak-config rules (telnet, root-login, world-writable), **redaction by default** | ✅ engine tested; live-positive on a real image tracked |
| 6 | **enrich** | KEV + EPSS + reachability heuristic → **deterministic priority ranking** with reasons; suppression applied | ✅ |
| 5b | **explain** | LiteLLM AI explainer — plain-English "why it matters", **never a verdict**, advisory-labeled | 🟡 optional; passes 50-finding gate before it's featured |
| 7 | **graph** | content-addressed nodes in SQLite → the reproducibility + diff engine | ✅ |
| 8 | **report** | static HTML + Markdown: top priorities, findings, **CRA Annex I mapping**, **VEX summary**, suppressed section | ✅ |
| 9 | **export** | CycloneDX/SPDX SBOMs, graph JSON, and the **evidence pack** (manifest, findings, CRA mapping, **OpenVEX + CycloneDX-VEX**, README) | ✅ |

---

## 2. The differentiators — what makes us *not* "just a scanner"

Scanning is commoditized (unblob/Syft/Grype are free). These are the things grype **cannot** produce — the evidence layer:

| Differentiator | Why it matters | Status |
|---|---|---|
| **Extraction confidence + honesty banner** | A "0 findings" on a 1%-extracted image is flagged as *"we couldn't look"*, not a green checkmark. The Dahua doorbell proves it. | ✅ |
| **EOL / no-fix as first-class evidence** | Grype leaves "fixed-in" blank; we say *"no fix available (EOL) → CRA II.8 maintenance failure"*. | ✅ |
| **Prioritization with stated reasons** | 122 CVEs → a defensible top-10 (KEV > EPSS≥10% > reachable > severity), each with its reason. | ✅ |
| **CRA Annex I mapping** | Findings → I.2a / II.2 / II.8, in the auditor's language, "best-effort, not legal advice". | ✅ |
| **VEX (OpenVEX + CycloneDX)** | A drafted exploitability statement — which CVEs matter, which are *not_affected* and **why** — deduped per-vulnerability, "manufacturer signs". | ✅ |
| **Evidence pack** | The folder a device maker hands an auditor: SBOM + findings + CRA mapping + VEX + a README listing what they still owe. | ✅ |
| **`diff` / memory** | Release-over-release story: components changed, CVEs resolved/introduced, with a **DB-drift honesty caveat** no incumbent has. | ✅ |
| **Suppression + local labels** | Mark a finding false-positive with a reason → it flows through ranking, CRA, and VEX; label captured **locally, never transmitted**. | ✅ |
| **Local-first, air-gapped** | Full scan under `--network=none`, proven by a CI egress test. Firmware never leaves the machine. | ✅ |
| **Reproducible** | Same image → identical content-addressed graph (CI acid test). | ✅ |

---

## 3. CLI commands

| Command | Purpose |
|---|---|
| `firmgraph scan <image>` | Full pipeline → graph + reports + evidence pack |
| `firmgraph diff <a> <b>` | Semantic release-over-release diff |
| `firmgraph history` | List recorded scans (the product remembers) |
| `firmgraph suppress <cve> --reason ...` | Mark false-positive; shareable YAML rule + local label |
| `firmgraph explain-gate <findings.json>` | Human-scored AI-explainer gate harness (BYO key) |
| `firmgraph version` | Version |

---

## 4. Architecture (built to be upgraded)

- **Pipes & Filters** — 10 sequential stages, each a Template-Method class with automatic provenance.
- **Ports & Adapters (Hexagonal)** — every external tool (unblob, Syft, Grype, cve-bin-tool, LiteLLM) behind a typed port. Swapping any of them = one file + one registration line. The **Modularity Contract**.
- **Content-addressed SQLite graph** — node id = hash of canonical content → reproducibility + diff for free.
- **Provenance manifest** — every scan records tool versions + DB snapshot dates → the audit receipt.
- **Graceful degradation** — a broken optional engine (e.g. cve-bin-tool) is an honest "skipped", never a crash or a silent wrong result.
- **Security-first** — firmware is treated as hostile input: extraction jail, non-root container, air-gapped by default.

---

## 5. Honestly not-done / tracked

| Item | State |
|---|---|
| **cve-bin-tool findings** | Integration + graceful-skip done; upstream v3.4 crashes → 0 findings. Unlock = validate a working version. |
| **AI explainer gate** | Harness built; needs a real key + human-scoring 50 findings before it's featured (stays beta until then). |
| **Live checks-positive** | Rules unit-tested on seeded trees; a real sloppy image (telnet-on/default-creds) still owed. |
| **Corpus depth** | 4 images (OpenWrt, TP-Link, ChirpStack, Dahua). Want 3–5 beachhead-class (LoRaWAN / EV charger). |
| **Compliance-pro review** | CRA mapping should get one sanity-check from a compliance professional before public launch. |
| **Name/org lock** | Lock GitHub org + Docker namespace; digest-pin the unblob base image at release. |

---

## 6. Proven on real firmware (the corpus)

| Image | Class | Extraction | Findings | Role |
|---|---|---|---|---|
| TP-Link Archer C7 | Proprietary router | 94% | 122 (8 crit) | Demo star |
| OpenWrt WNDR3800 | Open router | 69% | 8 | Clean baseline |
| ChirpStack (SenseCAP M2) | **LoRaWAN gateway** | 64% | 61 | Beachhead class |
| Dahua DB11 doorbell | IP camera | **0.92%** | 0 | **Honesty exhibit** (extraction failure, flagged) |

---

## 7. Where the company stands (the honest whole picture)

- **Product:** ~90% of V0.1.0 built and verified on real firmware. Strong.
- **Market:** validation just started. ~11 first outreach conversations (method being fixed in `outreach-playbook-v2.md`); **0 firmware images received from a prospect yet; the core "is the paperwork the pain?" question not yet answered by an owner.**
- **The gate that matters (Gate 1, wk4):** 10 real calls with the right people → does the "evidence is the moat" thesis survive a buyer's mouth?

**Bottom line:** the tool is real and demo-ready; the company is unvalidated. The next milestone lives in the discovery log, not the codebase.

---

## 8. Run it

```bash
# local (host has syft/grype; unblob via Docker)
uv sync && uv run firmgraph scan firmware.bin -o out && open out/report.html

# fully air-gapped container (recommended)
docker run --rm --entrypoint grype -v fg-cache:/home/unblob/.cache firmgraph db update  # once, online
docker run --rm --network=none -v fg-cache:/home/unblob/.cache -v "$PWD:/work" \
  firmgraph scan /work/firmware.bin -o /work/out
```

*Full limits and caveats: `docs/honest-limits.md`. Launch checklist: `docs/launch-bar.md`.*
