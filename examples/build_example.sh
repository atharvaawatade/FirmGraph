#!/usr/bin/env bash
# Builds examples/demo-firmware.tar — a tiny, synthetic, SAFE-to-ship firmware
# image that a stranger can scan on first clone and see REAL findings:
# telnet-on, root SSH login, a hardcoded (obviously fake) key, a root hash.
#
# Everything here is fabricated for demonstration. No real secrets.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/etc/init.d" "$ROOT/etc/ssl" "$ROOT/bin"

# --- config smells (real check hits, no real risk) ---
cat > "$ROOT/etc/inittab" <<'EOF'
::sysinit:/etc/init.d/rcS
::respawn:/usr/sbin/telnetd -l /bin/login
EOF

cat > "$ROOT/etc/sshd_config" <<'EOF'
Port 22
PermitRootLogin yes
PermitEmptyPasswords yes
EOF

# fabricated, non-functional root hash (clearly a demo value)
echo 'root:$1$DEMOsalt$0000000000DEMONOTAREALHASH0:19000:0:99999:7:::' > "$ROOT/etc/shadow"

# an OBVIOUSLY FAKE private key — not a usable secret, only the header pattern matters
cat > "$ROOT/etc/ssl/device.key" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
THIS-IS-A-FAKE-DEMO-KEY-NOT-A-REAL-SECRET-000000000000000000000000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----
EOF

echo '#!/bin/sh' > "$ROOT/etc/init.d/rcS"
printf '\x7fELFdemo-busybox-placeholder' > "$ROOT/bin/busybox"

# portable tar (works with BSD tar on macOS and GNU tar on Linux)
tar -cf "$HERE/demo-firmware.tar" -C "$ROOT" .

echo "wrote $HERE/demo-firmware.tar ($(wc -c < "$HERE/demo-firmware.tar") bytes)"
