# Corpus Benchmark

Real measurements on real firmware. Published in full — including the failure —
because "measured, not promised" is the whole point. Numbers are from the
FirmGraph pipeline (unblob → Syft → Grype → checks → rank), reproducible via the
scan manifest.

## Results

| Image | Class | Extraction | Components | Findings (C/H/M/L) | Role in corpus |
|---|---|---|---|---|---|
| OpenWrt 25.12.5 (Netgear WNDR3800) | Open router | ✅ 69% | 231 | 8 (0/1/3/4) | Happy-path baseline |
| TP-Link Archer C7 v5 | Proprietary router | ✅ 94% | ~200 execs, few named | 122 (8/55/50/9) | **Demo image** — openssl 1.0.2u, proftpd, curl; ~24 no-fix (EOL) |
| ChirpStack GW OS 4.11.0 (SenseCAP M2) | **LoRaWAN gateway (beachhead)** | ✅ 64% | 560 | 61 (3/21/33/4) | Beachhead-class; EOL busybox no-fix, nginx 4 majors behind — the *maintenance-obligation* story |
| Dahua DB11 doorbell | IP camera (out of class) | ❌ 0.92% | 0 | 0 | **Honesty exhibit** — a "0 findings" that means "we couldn't look", flagged with a red banner, not a green checkmark |

## What the corpus proves

1. **The tool works on its target class** (Linux-class network devices): 64–94% extraction,
   hundreds of components, findings that match hand-run Phase-0 numbers exactly.
2. **The honesty machinery works**: the Dahua image extracts to 0.92% and the report *says so*
   loudly. This is the single most important row — it's the difference between a scanner and an
   evidence tool.
3. **The maintenance story is real**: no-fix (EOL) CVEs on ChirpStack and TP-Link are surfaced as
   first-class evidence and mapped to CRA Annex I II.8 — something a raw CVE list never articulates.

## How to reproduce

```bash
docker run --rm --entrypoint grype -v fg-cache:/home/unblob/.cache firmgraph db update  # once, online
docker run --rm --network=none -v fg-cache:/home/unblob/.cache -v "$PWD:/work" \
  firmgraph scan /work/<image>.bin -o /work/out
```

Every scan's `evidence-pack/manifest.json` records the exact tool versions and DB snapshot date
used, so these numbers are reproducible and any drift is explainable.

## Known gaps in the corpus (tracked, honest)

- Only one beachhead-class image so far (ChirpStack). Target: 3–5 LoRaWAN/charger images.
- No live checks-positive yet (a genuinely sloppy old router with telnet-on / default creds).
  Synthetic seeding is fully tested; a real-world positive is a Phase-9 validation item.
