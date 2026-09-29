# V0.1.0 Finalization Plan — GitHub-ready

> Triggered by the OpenWrt x86 scan: **3118 findings**, dumped flat. That output is
> the firehose our whole thesis says we kill. Plus two real bugs. This plan makes
> the tool credible at enterprise scale, honestly, then we push.

## P1 — Correctness bugs (must fix)
- [ ] **Dedup components.** OpenWrt `/rom` overlay makes Syft list every deb twice
      (base-files, busybox, kernel… all ×2). Dedup `ctx.components` by identity.
- [ ] **Dedup findings.** Same overlay can double grype matches. Dedup by
      (finding_id, component, kind, source) so counts are honest.

## P2 — Report scales to thousands of findings (the thesis, made visible)
- [ ] **Executive summary** at top: component count, findings by severity,
      act-now (P1–P3) vs backlog (P4–P5), KEV count, no-fix/EOL count, extraction conf.
- [ ] **Findings grouped by component** with counts + max severity + a caveat flag
      for flood components (kernel).
- [ ] **Cap the flat findings table** at top 100 by priority; full set stays in
      `evidence-pack/findings.json`. Report becomes readable; audit trail stays complete.
- [ ] Apply to HTML + Markdown identically (determinism).

## P3 — Honesty about kernel-version CVE matching
- [ ] honest-limits: a "Linux kernel version matching" section — matching a kernel
      version yields thousands of CVEs, most not applicable without kernel-config
      analysis (out of V1 scope); we group + prioritize, never claim all are actionable.
- [ ] Report: flood components (> 50 findings) carry a one-line caveat.

## P4 — GitHub-push hygiene
- [ ] `.dockerignore` — keep build context small (exclude out/, *.db, .venv, .git, reports).
- [ ] Dockerfile `ARG BAKE_DB=true` — CI builds fast (`BAKE_DB=false`); release image
      ships the offline DB by default.
- [ ] CI: fast hermetic tests + a Docker build/egress test using the bundled example
      (checks findings, no 1.7GB DB needed) under `--network=none`.
- [ ] Verify nothing huge/secret staged.

## Status — DONE (2026-07-12)
✅ All items implemented. 67 tests green · ruff + mypy --strict clean.
- Component + finding dedup (overlay-fs doubling fixed).
- Report scales: exec Summary, per-component grouping (kernel flood → one ⚠ row),
  flat list capped at 100 with full record in evidence-pack/findings.json.
- honest-limits: kernel version-match + de-dup sections added.
- .dockerignore added; Dockerfile `BAKE_DB` arg; CI builds fast + air-gapped
  example test (no 1.7GB DB in CI).
- Verified on real TP-Link (host): Summary + grouping + cap all render.
- Remaining: rebuild release image, verify OpenWrt end-to-end, push.
