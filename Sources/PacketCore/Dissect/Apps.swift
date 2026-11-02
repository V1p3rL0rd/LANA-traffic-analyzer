import Foundation

/// Application-layer demux: port table first (lower port wins, like Wireshark), then heuristics,
/// then the protocol catalog for naming payloads we do not parse in depth.
enum Apps {
    typealias Handler = (DissectionContext, Int, Int, Bool) -> Bool   // (ctx, offset, end, isTCP) -> handled

    static let tcpTable: [UInt16: Handler] = [
        53: DNS.tcp, 853: { c, o, e, _ in TLS.dissect(c, o, e, name: "DoT") },
        80: HTTP.dissect, 8080: HTTP.dissect, 8000: HTTP.dissect, 8008: HTTP.dissect, 8888: HTTP.dissect, 3128: HTTP.dissect,
        443: TLS.tcp, 8443: TLS.tcp, 465: TLS.tcp, 993: TLS.tcp, 995: TLS.tcp, 636: TLS.tcp, 5061: TLS.tcp, 6443: TLS.tcp, 8883: TLS.tcp,
        22: Text.ssh, 21: Text.ftp, 25: Text.smtp, 587: Text.smtp, 110: Text.pop, 143: Text.imap, 23: Text.telnet,
        5060: Text.sip, 554: Text.rtsp, 6379: Text.redis,
        179: Misc.bgp, 1883: Misc.mqtt, 502: Misc.modbus, 9092: Misc.kafka,
        5355: DNS.tcp,
    ]

    static let udpTable: [UInt16: Handler] = [
        53: DNS.udp, 5353: DNS.udp, 5355: DNS.udp, 137: DNS.nbns,
        67: DHCP.v4, 68: DHCP.v4, 546: DHCP.v6, 547: DHCP.v6,
        123: Misc.ntp, 161: Misc.snmp, 162: Misc.snmp, 514: Misc.syslog, 69: Misc.tftp,
        1900: Text.ssdp, 5060: Text.sip,
        51820: Misc.wireguard, 4789: Misc.vxlan, 6081: Misc.geneve, 520: Misc.rip,
        3478: Misc.stun, 500: Misc.ike, 4500: Misc.ike,
        1812: Misc.radius, 1813: Misc.radius, 1645: Misc.radius, 1646: Misc.radius,
        3784: Misc.bfd, 4784: Misc.bfd, 443: TLS.quic, 8443: TLS.quic,
    ]

    static func dispatch(_ ctx: DissectionContext, tcp: Bool, _ sp: UInt16, _ dp: UInt16, _ o: Int, _ end: Int) {
        guard o < end else { return }
        let table = tcp ? tcpTable : udpTable
        let ports = sp < dp ? [sp, dp] : [dp, sp]
        for p in ports {
            if let h = table[p], h(ctx, o, end, tcp) { return }
        }
        // Heuristics for well-known protocols on non-standard ports.
        if tcp {
            if TLS.looksLikeRecord(ctx.data, o), TLS.tcp(ctx, o, end, tcp) { return }
            if HTTP.looksLikeHTTP(ctx.data, o), HTTP.dissect(ctx, o, end, tcp) { return }
            if ctx.data.asciiLine(o, max: 8)?.hasPrefix("SSH-") == true, Text.ssh(ctx, o, end, tcp) { return }
        } else {
            if TLS.looksLikeQUIC(ctx.data, o), TLS.quic(ctx, o, end, tcp) { return }
        }
        let map = tcp ? ProtocolCatalog.tcpPortMap : ProtocolCatalog.udpPortMap
        if let desc = ports.lazy.compactMap({ map[$0] }).first {
            ctx.layer(desc.id, "\(desc.name)", o, end - o, display: desc.name)
            ctx.add(ctx.tree.last!, "Data: \(end - o) bytes", "data.len", .int(Int64(end - o)), o, end - o)
            ctx.info += "  \(desc.name) data (\(end - o) bytes)"
            cleartextCheck(ctx, desc.id)
            return
        }
        ctx.layer("data", "Data (\(end - o) bytes)", o, end - o, display: tcp ? "TCP" : "UDP")
        ctx.index("data.len", .int(Int64(end - o)))
    }

    /// Protocols that transmit credentials in cleartext deserve attention on any network.
    static func cleartextCheck(_ ctx: DissectionContext, _ id: String) {
        let cleartext: Set<String> = ["telnet", "ftp", "pop", "imap", "rlogin", "tftp", "vnc", "snmp", "ldap", "http_proxy", "x11"]
        if cleartext.contains(id), let node = ctx.tree.last {
            ctx.flag(.note, .security, "Cleartext protocol", key: "_ws.cleartext", on: node)
        }
    }

    /// Replaces the info column with app-level text (TCP/UDP info is kept as a prefix for TCP flags context).
    static func info(_ ctx: DissectionContext, _ s: String) {
        ctx.setInfo(s)
    }
}
