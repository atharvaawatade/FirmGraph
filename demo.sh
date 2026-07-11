#!/usr/bin/env bash
# FirmGraph demo runner — regenerate the full showcase in one command.
#
#   ./demo.sh
#
# Produces fresh reports for three corpus images in ~/Desktop/firmgraph-reports/
# and prints the 3-act narration. Scan beforehand; never live-extract in front
# of a prospect — the report is the payoff.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
DL="$HOME/Downloads"
OUT="$HOME/Desktop/firmgraph-reports"
SUP="/tmp/firmgraph-demo-suppressions.yaml"

TPLINK="$DL/tplink.bin"
OPENWRT="$DL/openwrt-25.12.5-ath79-generic-netgear_wndr3800-squashfs-sysupgrade.bin"
DOORBELL="$DL/doorbell.bin"

run() { echo; echo "▶ $1"; ( cd "$REPO" && uv run firmgraph "${@:2}" ); }

echo "=================================================================="
echo " FirmGraph demo — the evidence layer, not another scanner"
echo "=================================================================="

# ---- ACT 1: the lie every free tool tells (honesty exhibit) --------------
if [[ -f "$DOORBELL" ]]; then
  echo
  echo "── ACT 1 ── \"The lie every free tool tells\""
  echo "Encrypted firmware. A naive scanner prints a green 0. Ours screams."
  run "scan doorbell (honesty exhibit)" scan "$DOORBELL" -o "$OUT/doorbell" -q
  echo "   → open $OUT/doorbell/report.html  (1% confidence, red banner)"
fi

# ---- ACT 2: what's really inside (the substance) -------------------------
if [[ -f "$TPLINK" ]]; then
  echo
  echo "── ACT 2 ── \"What's really inside\""
  echo "Router firmware → prioritized findings, CRA mapping, VEX, evidence pack."
  # seed one suppression so the trust/VEX story is visible
  printf 'rules:\n  - finding_id: CVE-2023-48795\n    component: proftpd@1.3.4b\n    reason: "SFTP disabled in our proftpd build config"\n' > "$SUP"
  run "scan tplink (demo star)" scan "$TPLINK" -o "$OUT/tplink" --suppressions "$SUP" -q
  echo "   → open $OUT/tplink/report.html  (top priorities, VEX, CRA, evidence-pack/)"
fi

# ---- ACT 3: the clean baseline (calibration) -----------------------------
if [[ -f "$OPENWRT" ]]; then
  echo
  echo "── ACT 3 ── \"The clean baseline\""
  echo "Modern OpenWrt → few findings. Proves we don't manufacture noise."
  run "scan openwrt (baseline)" scan "$OPENWRT" -o "$OUT/openwrt" -q
  echo "   → open $OUT/openwrt/report.html"
fi

echo
echo "=================================================================="
echo " Reports in: $OUT"
echo " History:    (cd $REPO && uv run firmgraph history)"
echo " Diff two:   (cd $REPO && uv run firmgraph diff <old> <new>)"
echo "=================================================================="
