# Launch Bar — V0.1.0

The plan's rule: launch when every box is true, not before, not after. Scored
honestly — a checked box means *verified*, not *written*.

## Core capability

- [x] `firmgraph scan <image>` runs end-to-end, zero manual setup (Docker image bundles unblob + Syft + Grype)
- [x] Extraction real & jailed: unblob → binwalk fallback, path-traversal / symlink-escape / decompression-bomb guards (8 security tests)
- [x] SBOM with per-component provenance + confidence (Syft); CycloneDX + SPDX exports
- [x] CVE matching with pinned DB snapshot (Grype); EOL/no-fix surfaced as first-class evidence
- [x] Prioritization: KEV > EPSS≥10% > reachable+severe > severe > rest, each with a stated reason
- [x] Reachability: Linux heuristic, honestly labeled; NOT APPLICABLE on non-Linux images
- [x] Security checks: secrets/config rulepack v1, redaction-by-default, zero-FP on clean tree
- [x] `firmgraph diff`: semantic component/CVE deltas + DB-drift caveat
- [x] CRA Annex I mapping table + evidence-pack scaffold (manifest, findings, mapping, README)
- [x] Suppression round-trip + local label capture (never transmitted)
- [x] AI explainer: optional, advisory, explainer-never-judge, degrades to nothing gracefully

## Non-negotiables

- [x] **Determinism**: same image → identical content-addressed graph (CI acid test)
- [x] **Privacy**: full scan under `--network=none` succeeds (CI egress test)
- [x] **Honesty**: low-confidence extraction shows a red banner; stubs (none left) would self-label
- [x] **Liability line** on every artifact (HTML, MD, evidence-pack README)
- [x] Quality: 49 tests, ruff clean, mypy --strict clean

## Docs (transparency = credential)

- [x] README with air-gapped quickstart
- [x] Honest Limits page
- [x] Corpus benchmark (incl. the Dahua honesty exhibit)
- [x] Governance promises (Apache-forever, local-forever)
- [x] CONTRIBUTING (the three high-value contributions)
- [x] LICENSE (Apache-2.0)

## Tracked before public launch (not blockers for internal V0.1.0, honest open items)

- [ ] **AI gate**: run `firmgraph explain-gate` with a real key, human-score 50 findings. AI stays beta-labeled until this passes.
- [ ] **cve-bin-tool value**: integration is complete and degrades gracefully (broken engine → honest "skipped", never a failure). Pinned 3.4 has an upstream scan crash → currently produces no findings. Validate a working version to unlock the second-engine component coverage. Not claimed until it works.
- [x] **Live checks-positive**: `examples/demo-firmware.tar` (bundled) — unblob extracts it and the checks engine fires 5 real findings (private key, root hash, telnet-on, root SSH login, empty passwords). Proven on a real extraction, not just unit trees. (A sloppy *real-world* vendor image is still a nice-to-have for the corpus.)
- [ ] **Corpus depth**: 3–5 beachhead-class images (LoRaWAN / charger), currently 1 (ChirpStack).
- [ ] **Stranger test**: one person who didn't build it clones and gets a result with zero questions.
- [ ] **Name/org lock** + digest-pin the unblob base image at the release tag.

## Verdict

Engine and honesty machinery: **done and verified.** The open items are validation and
polish, not missing capability. V0.1.0 is real: a device maker's firmware in → reproducible,
prioritized, CRA-mapped evidence out, fully local, in seconds.
