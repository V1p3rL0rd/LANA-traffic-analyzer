# Changelog

## 1.0.0 — 2026-11-02

- First public release.
- Live capture via libpcap on Ethernet, Wi‑Fi (incl. 802.11 monitor mode), loopback, VPN tunnels, bridges; pcap/pcapng open & save.
- Capture filter builder: srcaddr / dstaddr / bidirectional / 185 protocols → BPF, with strict address validation.
- Own Swift dissectors for ~45 protocols, L2–L7.
- Anomaly engine: TCP sequence analysis, ARP spoofing, scans, protocol errors, cleartext credentials; red/yellow row highlighting and an aggregated anomalies panel.
- Wireshark‑style display filter subset.
- Builds with Command Line Tools only (no SwiftUI macros); ChmodBPF installer for capture without root.
