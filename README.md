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

## Install

### Option 1: download a release

1. Download `LANA-Traffic-Analyzer-<version>-macOS.zip` from the [Releases](../../releases) page and unzip it.
2. Move **LANA Traffic Analyzer.app** to **Applications**.
3. The app is ad‑hoc signed, not notarized, so the first launch is blocked by Gatekeeper. Either right‑click → **Open**, or use *System Settings → Privacy & Security → Open Anyway*, or run:
   ```bash
   xattr -dr com.apple.quarantine "/Applications/LANA Traffic Analyzer.app"
   ```
4. Grant packet‑capture access once — see [Capture permissions](#capture-permissions). If Wireshark with ChmodBPF is installed, you already have it.

### Option 2: build from source

Requires macOS 14+ and the Command Line Tools (`xcode-select --install`), Swift 5.9+. Full Xcode is **not** required.

```bash
git clone https://github.com/V1p3rL0rd/LANA-traffic-analyzer.git && cd LANA-traffic-analyzer
./Scripts/build-app.sh --install        # builds and installs "/Applications/LANA Traffic Analyzer.app"
```

| Command | Result |
|---|---|
| `./Scripts/build-app.sh` | `build/LANA Traffic Analyzer.app` for the host architecture |
| `./Scripts/build-app.sh --install` | build + install to `/Applications` (shows up in Launchpad and Spotlight) |
| `./Scripts/build-app.sh --universal` | arm64 + x86_64 binary (needs full Xcode) |
| `INSTALL_DIR=~/Applications ./Scripts/build-app.sh --install` | install for the current user only |
| `swift test` | core unit tests |

Build as your own user, not root: the script refuses to run as root, because `.build/` and `build/` would become root‑owned and later builds would fail with `Permission denied`.

## Capture permissions

Capturing goes through `/dev/bpf*`, which only root can open by default. Running a GUI as root is a bad idea, so LANA uses the same scheme as Wireshark: an `access_bpf` group plus a launch daemon that grants it access to the BPF devices at boot.

```bash
sudo ./Scripts/install-chmodbpf.sh      # idempotent; compatible with Wireshark's ChmodBPF
# log out and back in so the access_bpf membership takes effect
ls -l /dev/bpf0                         # crw-rw----  root  access_bpf
```

Roll back with `sudo ./Scripts/uninstall-chmodbpf.sh [--remove-group]`. If Wireshark's ChmodBPF is installed, permissions and the group are left alone.

## How it works

```
 /dev/bpf* ──► libpcap (CaptureEngine, capture thread)
                   │  RawPacket batches (pcap_dispatch, immediate mode)
                   ▼
        CapturePipeline (serial analysis queue)
          Dissector (stateless, L2→L7)  ──►  AnomalyEngine (stateful: TCP, ARP, scans)
          + live display filter                     │ ExpertInfo (error / warning / note)
                   │  pending buffer (lock)         ▼
                   ▼
        CaptureSession (@MainActor, drained at 4 Hz) ──► NSTableView (row highlighting)
                                                     ├─► protocol tree + hex (re‑dissected on click)
                                                     └─► anomalies panel (aggregates)
```

- **No root at runtime.** BPF access comes from the `access_bpf` group; the capture filter is compiled by `pcap_compile` and runs in the kernel.
- **Own dissectors.** No GPL dependencies and no Wireshark install; ~45 protocols are parsed in depth, the rest of the 185‑protocol catalog is identified by port / EtherType.
- **Low memory.** Only the raw frame and a compact summary are kept per packet; the protocol tree is rebuilt on selection.
- **Responsive UI.** Dissection and analysis run off the main thread; NSTableView handles millions of rows with full‑row colouring.

## Things to know

- **App Sandbox is disabled on purpose:** sandboxed apps cannot open `/dev/bpf*`, so distribution is outside the App Store only.
- **`access_bpf` membership** lets an account sniff all traffic on the host. Add trusted accounts only.
- **Checksums** are not validated by default: macOS captures outgoing packets before checksum offload, so they would look broken. Enable it in capture options.
- **Memory.** Packets are kept in memory (2 million by default); capture stops with a notice at the limit. For multi‑hour captures use `tcpdump -G/-C` rotation and open the files in LANA.
- **No IP/TCP reassembly:** a message split across several segments is dissected from its first segment.
- **Monitor mode** (802.11) works on the Wi‑Fi interface only and disconnects it from the network while capturing.

> **Only analyze networks you own or are explicitly authorized to monitor.**

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
Assets/                 app icon (SVG source + .png + .icns)
.github/workflows/      CI (tests + build) and release (published release → zipped .app attached)
```

Display‑filter syntax, the full anomaly list and verification steps: [README.ru.md](README.ru.md).

## Maintenance

- **Logs:** `log stream --predicate 'subsystem == "app.lana"'` (capture start/stop, pcap errors).
- **Dropped packets:** the status bar shows kernel drops (`pcap_stats`). If they grow, narrow the capture filter — BPF discards unwanted traffic in the kernel.
- **Update:** `git pull && ./Scripts/build-app.sh --install` atomically replaces the installed app.
- **Uninstall:** delete `/Applications/LANA Traffic Analyzer.app`, run `defaults delete app.lana.LANA` and `sudo ./Scripts/uninstall-chmodbpf.sh`.

## Releasing

Open **Releases → Draft a new release**, create a tag such as `v1.0.0`, click **Generate release notes** and **Publish**. GitHub Actions then builds a universal app and attaches `LANA-Traffic-Analyzer-<version>-macOS.zip` (plus a SHA-256 checksum) to the release within a few minutes.

## License

[MIT](LICENSE) © 2026 Vianor Gvazbaya
