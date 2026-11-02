<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="LANA Traffic Analyzer icon">
</p>

<h1 align="center">LANA Traffic Analyzer</h1>
<p align="center"><b>Native network traffic analyzer for macOS</b> — Wireshark‑style capture and dissection without the cluttered UI. Companion to <a href="https://github.com/V1p3rL0rd/LANA-scanner">LANA Scanner</a>.</p>

<p align="center">
  <img alt="macOS 14+" src="https://img.shields.io/badge/macOS-14%2B-black?logo=apple">
  <img alt="Swift 5.9+" src="https://img.shields.io/badge/Swift-5.9%2B-F05138?logo=swift&logoColor=white">
  <img alt="Xcode not required" src="https://img.shields.io/badge/Xcode-not%20required-2FE6B0">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.ru.md">Русская версия</a></p>

---

LANA Traffic Analyzer captures packets on any macOS interface (Ethernet, Wi‑Fi, monitor mode, loopback, VPN tunnels, bridges), dissects them with its own Swift protocol engine and highlights network anomalies as they happen: **red** for errors, **yellow** for things that need attention. It is a single native SwiftUI + AppKit app on top of libpcap — no root at runtime, no Wireshark, no third‑party dependencies.

## Features

| Feature | Details |
|---|---|
| Capture filter | `srcaddr` / `dstaddr` (IPv4, IPv6, CIDR, MAC, hostname), bidirectional mode, 185 protocols in 18 categories with search, or raw BPF validated live by `pcap_compile` |
| Interfaces | Ethernet, Wi‑Fi, 802.11 monitor mode (Radiotap), `lo0`, `utun*`/`ipsec*` (WireGuard, Tailscale, IPsec), bridges, VM interfaces; pcap / pcapng files |
| Dissectors | ~45 protocols fully parsed across L2–L7 (ARP, VLAN, LLDP, CDP, STP, IPv4/IPv6, ICMP/ICMPv6, TCP, UDP, SCTP, DNS, DHCP, TLS with SNI/ALPN, QUIC, HTTP, SSH, SMTP/IMAP/POP3/FTP, SNMP, BGP, OSPF, VXLAN, WireGuard, Modbus…); the rest identified by port / EtherType |
| Anomaly detection | TCP analysis (retransmissions, dup ACKs, lost segments, zero window, window full, keep‑alive), RST, malformed packets, ARP spoofing, port scans, ping sweeps, DNS/HTTP/TLS errors, cleartext credentials, deprecated TLS |
| Display filter | Wireshark syntax subset: `ip.addr == 10.0.0.0/8 && tcp.port in {80 443}`, `contains`, `matches`, `expert.error` |
| UI | Packet list (NSTableView, millions of rows), protocol tree, hex dump with field highlighting, aggregated anomalies panel, conversation filter from the context menu |

## Anomaly highlighting

| 🔴 Error | 🟡 Attention |
|---|---|
| Malformed / truncated headers, bad checksums* | TCP retransmission / fast / spurious, out‑of‑order, dup ACK |
| TCP RST, zero window | Previous segment not captured, window full, zero‑window probe |
| SYN+FIN, NULL, Xmas scans; LAND (src == dst) | FIN scan, port scan (>100 targets / 5 s), ping sweep |
| ARP: IP moved to another MAC (spoofing) | Gratuitous ARP reply, ICMP / ICMPv6 redirect |
| ICMP unreachable, parameter problem | TTL exceeded, PMTU / Packet Too Big |
| DNS SERVFAIL / REFUSED / FORMERR | NXDOMAIN, truncated responses, AXFR, tunnelling‑like names |
| HTTP/SIP 5xx, TLS fatal alert, SMTP/FTP 5xx | HTTP 4xx, TLS ≤ 1.1, weak ciphers, Heartbeat |
| DHCP NAK, EAP failure, RADIUS reject, BGP NOTIFICATION, BFD down | Cleartext credentials: HTTP Basic, FTP/POP3 PASS, IMAP LOGIN, Telnet, SNMP v1/v2c |

\* Checksum validation is off by default: macOS captures outgoing packets before checksum offload.

## Build & install

Requirements: macOS 14+ and Command Line Tools (`xcode-select --install`). Full Xcode is **not** required.

```bash
# 1. BPF access without root (once; idempotent; compatible with Wireshark's ChmodBPF)
sudo bash Scripts/install-chmodbpf.sh      # then log out and back in

# 2. Core tests
swift test

# 3. Build the app (arm64, ad-hoc signed, icon from Assets/)
bash Scripts/build-app.sh
open build/LANA.app
```

Build as your own user, not root — otherwise `.build/` and `build/` become root‑owned and later builds fail with `Permission denied`. Universal (arm64 + x86_64) builds need full Xcode: `UNIVERSAL=1 bash Scripts/build-app.sh`.

> ⚠️ App Sandbox is disabled on purpose: sandboxed apps cannot open `/dev/bpf*`. Distribution is outside the App Store only (Developer ID + notarization).
>
> ⚠️ Every member of the `access_bpf` group can sniff all traffic on the host. Add trusted accounts only. Roll back with `sudo bash Scripts/uninstall-chmodbpf.sh`.

## Project layout

```
Sources/CPcap/          libpcap module map
Sources/PacketCore/     platform‑neutral core (also builds and tests on Linux)
  Capture/              CaptureEngine, InterfaceDiscovery, PcapFile, BPFValidator
  Dissect/              L2, IP, ICMP, Transport, DNS, DHCP, TLS/QUIC, HTTP & text protocols, WLAN
  Analysis/             AnomalyEngine (TCP / ARP / scans), PacketProcessor
  Filter/               ProtocolCatalog, CaptureFilter (→ BPF), DisplayFilter
Sources/LANA/           SwiftUI + AppKit app
Tests/PacketCoreTests/  XCTest: dissectors, TCP analysis, filters, pcap round‑trip, fuzzing
Scripts/                build-app.sh, install/uninstall-chmodbpf.sh
Assets/                 app icon (AppIcon.svg source, .png, .icns)
```

Detailed architecture, filter syntax and operations notes: [README.ru.md](README.ru.md).

## License

[MIT](LICENSE) © 2026 Vianor Gvazbaya
