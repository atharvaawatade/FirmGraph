# V0.1.0 Release Audit — "The YC Cold-Clone Test"

> **Premise:** a skeptical evaluator clones the repo cold and runs exactly what the docs say — nothing more, nothing we know as insiders. Anything that breaks, overclaims, or needs tribal knowledge is a FAIL. Self-written tests passing is NOT evidence; the docs working for a stranger IS.
>
> **Rule:** I execute each step literally, from a clean checkout (`git archive`), record PASS/FAIL with evidence, fix every FAIL, and re-run until the whole plan is green. No step skipped, no failure hand-waved.

## Audit steps (executed in order, strictly)

- [ ] **A1 — Docs honesty pass.** Read README + STATUS with a red pen. Every command must be literally runnable; every claim must match reality. No stale files (demo.bin), no flags-after-image docker bugs, no "land next" for shipped features.
- [ ] **A2 — Cold clone integrity.** `git archive HEAD` into a clean dir = exactly what a stranger gets. Confirm the bundled example is present, no required file is git-ignored, no absolute paths leak.
- [ ] **A3 — Local quickstart (exact README commands).** Fresh venv, run the README's local commands verbatim. Must produce a report with REAL findings + evidence pack. Time it.
- [ ] **A4 — Docker quickstart (exact README commands).** Run the README's docker commands verbatim as written. They must actually work (this is where the grype-flags bug lives).
- [ ] **A5 — Air-gapped + read-only (our recommended secure mode).** `--network=none` + `-v "$PWD:/work:ro"`. Must extract and find (the bug we just fixed — confirm it stays fixed in the shipped image).
- [ ] **A6 — Determinism claim.** Scan the same image twice; assert identical graph node ids. We claim this publicly — prove it on a real image, not just the unit test.
- [ ] **A7 — Honesty claim (the Dahua exhibit).** Scan the encrypted doorbell; confirm low-confidence banner + no false "0 = safe". Our credibility rests on this.
- [ ] **A8 — Graceful degradation.** No key → AI off cleanly. cve-bin-tool broken → "skipped", not "failed". No scary red rows in a demo.
- [ ] **A9 — Claim-by-claim table.** Every headline claim in README/STATUS → a command that proves it. Any claim without proof gets softened or cut.
- [ ] **A10 — Artifact validity.** SBOM (CycloneDX/SPDX), OpenVEX, CycloneDX-VEX are structurally valid + parse; VEX has no duplicate CVEs.

## Results log

### 🔴 CRITICAL bug found & fixed — grype DB missing (A4/A5)
- **Symptom:** `detect` stage failed on EVERY container scan: `grype failed (exit 1): database does not exist`.
- **Root cause:** no grype DB baked in the image; with `GRYPE_DB_AUTO_UPDATE=false` (determinism) + air-gapped, grype can't self-heal. Earlier "passing" runs only worked because a `/tmp/fg_cache` volume happened to hold a hand-updated DB. A real clone-and-run (the YC test) always failed CVE matching.
- **Fix:** bake the grype vulnerability DB into the image at build time (`GRYPE_DB_CACHE_DIR=/opt/grype/db`, `grype db update` as root, readable by the unblob user). CVE matching now works air-gapped, zero setup. DB build date still recorded per-scan (determinism intact). Image ~2.8GB — the honest cost of a real offline promise.

### 🔴 CRITICAL bug #2 — grype 5-day staleness fuse (found while fixing #1, fixed)
- **Symptom:** grype hard-refuses any DB older than 5 days: `vulnerability database was built 5 days ago (max allowed age is 5 days)` → exit 1. With auto-update off (determinism) it can't self-heal.
- **Why it's insidious:** the baked-DB fix (#1) would have worked at demo time and then **silently broken 5 days later** — every air-gapped scan failing. Exactly the failure that surfaces *after* a good YC demo. Also explains the host path failing (its DB was 5 days old).
- **Fix:** `GRYPE_DB_VALIDATE_AGE=false` in the grype adapter — we deliberately pin a DB snapshot and record its date in the manifest, so grype must not refuse it by age. Offline promise is now durable, not a fuse. Verified: 5-day-old host DB → 122 findings.

### 🟠 bug #3 — DB date recorded as "unknown" (fixed)
- grype v6 moved the build date to `descriptor.db.status.built` (was `descriptor.db.built`). Our "determinism receipt" claim was silently false ("unknown"). Parser now reads the new path (+ old fallback). Verified: manifest shows `2026-07-06T07:49:14Z`. Regression test added.

### 🟠 A1 — Docs honesty: multiple broken/stale README commands (fixed)
- `docker run --entrypoint grype firmgraph -v ... db update` — **flags after image name = broken docker syntax**; also referenced a non-existent `firmgraph` image and an unnecessary step. **Deleted** (DB now baked in).
- Quickstart referenced `demo.bin` which no longer exists → now uses the bundled `examples/demo-firmware.tar`.
- Stale "61 tests" → 62. "pinned DB" → "baked-in DB".
- Docker quickstart rewritten: correct flag order, read-only firmware mount, separate writable `/out`.

### Step status
- [x] A1 — docs honesty (README fixed; STATUS pending post-build re-check)
- [x] A2 — cold clone integrity (git archive verified earlier; example present, nothing needed ignored)
- [x] A3 — local quickstart produces real findings (verified: 5 checks findings from git-archive clone)
- [ ] A4 — docker quickstart (RE-VERIFY after DB-baked rebuild)
- [ ] A5 — air-gapped + read-only + **CVE matching** (the fix — verify on real firmware)
- [ ] A6 — determinism (verify on real image)
- [ ] A7 — Dahua honesty exhibit
- [ ] A8 — graceful degradation (AI off, cve-bin-tool skipped)
- [ ] A9 — claim-by-claim table
- [ ] A10 — artifact validity (SBOM/VEX parse, no dup CVEs)
