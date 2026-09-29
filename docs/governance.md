# Governance & Trust Promises

The business is trust. This page is trust's paperwork. These promises are
load-bearing — breaking one breaks the company, not just the repo.

## The promises

1. **Apache-2.0, forever, for the FirmGraph core.** We will not relicense the open core to a
   source-available or restricted license. (We learned this from watching a decade of trust
   evaporate elsewhere.) The commercial product is a separate layer, not a paywall bolted onto
   code you already depend on.

2. **Local-first, forever.** The open tool sends nothing anywhere. No telemetry by default,
   ever. A CI test proves a full scan completes under `--network=none`. If opt-in telemetry ever
   exists, it will be explicit, documented, and off by default.

3. **Honest limits, published.** [docs/honest-limits.md](honest-limits.md) ships in the repo and
   stays current. If the README oversells, the README is a bug.

4. **We draft, the manufacturer signs.** Every artifact carries the liability line. FirmGraph
   produces evidence, never a compliance determination.

5. **Trademark, not code, is ours.** The code is everyone's (Apache-2.0). The name "FirmGraph"
   and the Simplivu brand are ours, so that "FirmGraph" always means the real thing.

## The two-layer structure

- **FirmGraph** (this repo): open-source evidence layer. Free forever. Complete for one engineer
  on one product.
- **Simplivu**: the commercial trust layer that carries the continuing legal obligations the free
  tool exposes — continuous monitoring, the ENISA reporting clock, audit vault, fleet, trained
  triage. You never *need* it to use FirmGraph; you need it when the *law's* ongoing duties exceed
  what one engineer can carry on one machine.

Analogy we hold ourselves to: **FirmGraph is Spark; Simplivu is Databricks** — the difference
being that our users comply with a law, not chase a trend.

## Contributions

- By contributing you agree to the DCO (Developer Certificate of Origin): sign off commits with
  `git commit -s`.
- Contributions are Apache-2.0. No CLA that assigns copyright away from you — we take a license,
  not your ownership.
