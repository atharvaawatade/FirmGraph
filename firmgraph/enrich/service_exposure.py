"""Service-exposure reachability (Rung 4) — the REMOTE attack surface.

Not all reachable code is equally dangerous. A severe CVE in a library that's only ever
called by a local one-shot tool is a very different risk from the same CVE in the HTTP
daemon that's bound to the WAN and started at boot. The question that actually orders a
device maker's work is: *which vulnerable components are network-facing services that are
actually running?* Those are what a remote attacker can reach.

What it does, and only this:
- find the Linux rootfs, read what init/systemd/inittab actually STARTS at boot;
- cross-reference against a curated set of well-known embedded network daemons
  (dropbear, dnsmasq, uhttpd, hostapd, miniupnpd, …);
- a component that is BOTH a known network daemon AND started is flagged as the remote
  attack surface: its findings are confirmed ``reachable=True`` and promoted in ranking.

Honesty discipline: this only ever UPGRADES (marks exposure) — it never downgrades, because
a service can be launched by mechanisms we don't parse (a parent process, a proprietary
supervisor), so "not seen in init" is not proof of "not running". Name-based detection is
high-precision on embedded images but misses services fronted by busybox applets or renamed
binaries — documented, not hidden. No rootfs => NOT APPLICABLE and silent.
"""

from __future__ import annotations

from pathlib import Path

from firmgraph.enrich.reachability import find_linux_roots
from firmgraph.models import Finding

_MAX_SVC_BYTES = 512 * 1024

# directories/files that describe what the device STARTS at boot
_SERVICE_SOURCES = (
    "etc/init.d",
    "etc/rc.d",
    "etc/systemd/system",
    "lib/systemd/system",
    "usr/lib/systemd/system",
    "etc/xinetd.d",
    "etc/config",  # OpenWrt UCI
)
_SERVICE_FILES = ("etc/inittab", "etc/rcS", "etc/rc.local")

# curated network-listening daemons common on Linux network devices
_NETWORK_DAEMONS: frozenset[str] = frozenset({
    # remote shell / console
    "dropbear", "sshd", "telnetd", "utelnetd",
    # http(s)
    "httpd", "uhttpd", "lighttpd", "nginx", "boa", "mini_httpd", "thttpd", "goahead",
    # dns / dhcp
    "dnsmasq", "named", "bind", "udhcpd", "dhcpd", "dhcpcd",
    # wifi / discovery / upnp
    "hostapd", "miniupnpd", "upnpd", "wsdd", "igmpproxy", "radvd", "minidlna",
    # ftp / smb
    "vsftpd", "proftpd", "ftpd", "bftpd", "smbd", "nmbd", "samba",
    # snmp / ntp / tr-069
    "snmpd", "ntpd", "chronyd", "cwmpd", "easycwmp", "tr069",
    # mqtt / coap / iot
    "mosquitto", "coap", "coapd",
    # vpn / rpc / super-servers
    "openvpn", "stunnel", "xinetd", "inetd", "rpcbind", "portmap",
})


def _read_small(path: Path) -> str:
    try:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= _MAX_SVC_BYTES:
            return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    return ""


def _boot_text(roots: list[Path]) -> str:
    chunks: list[str] = []
    for root in roots:
        for src in _SERVICE_SOURCES:
            d = root / src
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    chunks.append(f.name)  # the unit/script name itself is a signal
                    chunks.append(_read_small(f))
        for single in _SERVICE_FILES:
            chunks.append(_read_small(root / single))
    return "\n".join(chunks).lower()


def analyze_service_exposure(
    extracted: Path, findings: list[Finding]
) -> tuple[list[Finding], str, frozenset[str]]:
    """Flag findings on network-facing running services. Returns (findings, note, exposed)."""
    roots = find_linux_roots(extracted)
    if not roots:
        return list(findings), (
            "service-exposure: NOT APPLICABLE — no Linux init system found; no network "
            "attack-surface claim made"
        ), frozenset()

    boot = _boot_text(roots)
    exposed = frozenset(d for d in _NETWORK_DAEMONS if d in boot)

    updated: list[Finding] = []
    hits = 0
    for f in findings:
        if f.kind != "cve" or f.suppressed or not f.component:
            updated.append(f)
            continue
        comp = f.component.split("@")[0].strip().lower()
        if comp in exposed:
            updated.append(f.model_copy(update={"reachable": True}))
            hits += 1
        else:
            updated.append(f)

    surface = ", ".join(sorted(exposed)) if exposed else "none detected"
    return updated, (
        f"service-exposure: network-facing running services = [{surface}]; "
        f"{hits} findings on the remote attack surface (name-based; misses busybox-applet "
        f"and renamed daemons by design)"
    ), exposed
