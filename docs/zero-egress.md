# Zero egress — your firmware never leaves your machine

> The single sentence a cloud scanner cannot say: **"Run it yourself. Your firmware image
> never touches our infrastructure, because there is no infrastructure in the loop."**

Firmware is a device maker's crown-jewel IP. Asking someone to upload it to a vendor cloud
to be scanned is like asking for their bank credentials — and it's the reason most "free
firmware scan" wedges die on contact. FirmGraph's answer is structural, not a pinky-promise:
the tool runs entirely on your machine, and it has no way to send your firmware anywhere.

Don't trust that — **verify it**. Run [`./prove-zero-egress.sh`](../prove-zero-egress.sh).

## The trust model

| | Where it lives | Who sees it |
|---|---|---|
| **Your firmware binary** (the IP) | Only on your machine / your CI | **Only you** — never transmitted, by construction |
| **Derived metadata** (SBOM, findings, evidence pack) | Files in your `out/` dir | You — and only what *you* choose to share downstream |

FirmGraph produces the *evidence about* your firmware. It never exports the firmware itself.
This is also how the commercial layer (Simplivu) stays honest: it operates on the derived
compliance metadata you already have to produce for the CRA — never on the binary.

## Three independent ways to verify (what the script runs)

1. **By construction (source).** A network call is impossible without importing a network
   library. The scan pipeline imports **none** — no `requests`, `urllib`, `httpx`, `socket`,
   nothing. `grep` proves it live. (`sqlite3.connect()` is a *local file* database, not a
   network connection — correctly not counted.)

2. **By configuration (the wrapped tools).** The external binaries are pinned to offline:
   - `unblob` runs with `--network=none`
   - `grype` runs with `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_CHECK_FOR_APP_UPDATE=false`,
     `GRYPE_DB_VALIDATE_AGE=false` (a DB baked into the image, no fetch, no 5-day fuse)
   - `cve-bin-tool` runs with `--offline` (pinned local DB only)

3. **By execution (air-gapped run).** The strongest proof — run the whole scan with the
   network physically switched off and watch it succeed:
   ```bash
   docker run --rm --network=none \
     -v "$PWD/examples:/work:ro" -v "$PWD/out:/out" \
     firmgraph scan /work/demo-firmware.tar -o /out
   ```
   It completes and produces a full evidence pack. Something that runs under `--network=none`
   cannot be exfiltrating anything. **CI runs exactly this on every commit**
   (`.github/workflows/ci.yml` — the air-gapped test), so the promise can't silently rot.

## The one honest exception: the optional AI explainer

The *only* network-capable code in the whole project is `firmgraph/triage/explainer.py` — an
**opt-in** AI explainer (LiteLLM, bring-your-own-key). It is:
- **off by default** — it does nothing unless you pass `--explain` and set an API key;
- **not even importable** unless you install the `ai` extra;
- **advisory-only** — its output is labelled "verify before acting" and never enters the
  content-addressed graph or the evidence pack, so it can't affect a determinism or a verdict.

And it only ever sends the *finding text* (CVE id + summary) to your chosen model — never your
firmware. If you never opt in, the network code never runs. No key, no network → FirmGraph is
fully functional.
