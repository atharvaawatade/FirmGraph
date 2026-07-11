# Honest Limits

Transparency is our credential. This page states what FirmGraph does **not** do,
before anyone finds out the hard way. If a claim on the README ever contradicts
this page, this page wins and the README is a bug.

## Extraction

- Success is **measured, not promised** — see the [corpus benchmark](corpus-benchmark.md).
  Real range today: 94% (proprietary router) down to **0.92% (encrypted IP camera — a failure,
  kept in the corpus on purpose)**.
- **Encrypted or heavily obfuscated firmware does not extract.** When that happens the report
  shows a low confidence score and a red warning. **A "0 findings" result on a low-confidence
  extraction is a false negative, not a safe device.**
- Extraction confidence comes from unblob's chunk-identification ratio. binwalk fallback has no
  coverage ratio, so its confidence is capped at 0.5 — an honest guess is labeled as one.

## SBOM & CVE matching

- Components found via **binary classification** (no package metadata) carry lower confidence
  (0.6) than package-DB-backed ones (0.9) — the per-component `provenance` field tells you which.
- Unidentified executables are our **false-negative surface**: on one real router, ~200
  executables yielded only a handful of named components. The CVEs we report come from the
  components we could name; the ones we couldn't name are not "clean", they are **unknown**.
- CVE matching uses a **pinned vulnerability-DB snapshot** (date in the manifest). New scans
  against a newer DB can show new CVEs on unchanged firmware — `firmgraph diff` warns about
  this explicitly instead of letting you misread it as a firmware regression.

## Reachability

- It is a **Linux-filesystem heuristic**: binaries in PATH-like dirs, libraries in lib dirs,
  names referenced in init/systemd files. That's all.
- It **misses** `dlopen()`-style loading and proprietary launchers, by design.
- On RTOS/monolithic images (no Linux markers) it reports **NOT APPLICABLE** — silence,
  not false reassurance.
- On small systems where every vulnerable component is core systemware (busybox, openssl),
  everything is reachable and the signal discriminates weakly. It earns its keep on richer
  filesystems.

## Second scan engine (cve-bin-tool)

- FirmGraph integrates cve-bin-tool as an **optional second engine** for binary-signature
  matching — the intent is to name stripped binaries Syft can't, shrinking the false-negative
  surface (a real router often has more components than Syft alone reports).
- **Current status: not producing findings.** The pinned version (3.4) has an upstream scan-time
  crash (`NoneType.splitlines`) that fires even on trivial input — a code defect in the tool, not
  our integration or the vulnerability DB.
- **How FirmGraph handles it:** cleanly. A broken bonus engine is reported as
  *"cve-bin-tool: skipped (installed but unhealthy) — Syft+Grype results stand"* — an honest,
  non-alarming note, never a failure. Syft+Grype coverage is unaffected.
- **Tracked enhancement:** validate a working cve-bin-tool version, then enable it. Until then,
  we do not claim cve-bin-tool coverage. We would rather ship an honest "skipped" than a broken
  number.

## Security checks (secrets / config)

- Rulepack v1 is **deliberately conservative** — high-confidence rules only. Zero findings on a
  well-configured image is the intended behavior, not a blind spot. The trade-off: subtle or
  novel issues are out of scope for v1 rules.
- Content rules only scan **text-like files up to 512 KB**; binaries are never content-scanned.
  A secret embedded inside a compiled binary will not be found by the checks stage.
- A live positive on a real-world sloppy image is still a tracked validation item (the corpus
  needs one known-bad device; synthetic seeding is fully tested).

## CRA mapping

- **Best-effort, not legal advice.** Harmonised standards under the CRA are not final. The table
  organises evidence against Annex I essential requirements; it does not determine compliance.
- FirmGraph **drafts, maps, and evidences — the manufacturer signs.** The evidence pack README
  lists exactly what stays the manufacturer's responsibility (risk assessment, Declaration of
  Conformity, CVD policy, ENISA reporting readiness).

## AI explainer (optional, beta)

- **Explainer, never judge**: it never decides true/false positive; classification is fully
  deterministic (KEV / EPSS / reachability / rules).
- Output is **advisory**, labeled as such, cached per (finding, model, prompt version), and
  stored **outside** the graph — model drift cannot affect reproducibility.
- Without a key (or with the API down) the tool is fully functional. The AI layer ships only
  if it passes a human-scored 50-finding gate (`firmgraph explain-gate`).

## Reproducibility (what we promise, precisely)

- Same image + same tool versions + same DB snapshot → **identical content-addressed graph**
  (tested in CI on every commit).
- We do **not** promise byte-identical *reports* across tool upgrades or DB refreshes — the
  manifest records every version and snapshot date so any difference is explainable.

## Privacy

- Open core sends **nothing** anywhere. CI proves a full scan completes with `--network=none`.
- Suppression labels are captured **locally only** (`labels.jsonl`). Aggregation, if ever,
  will be explicit opt-in — never a default, never silent.
