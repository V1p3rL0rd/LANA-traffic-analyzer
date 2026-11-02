import Foundation

/// Stateless protocol dissector. Stateful analysis (TCP sequence tracking, ARP spoofing, scans)
/// lives in `AnomalyEngine`, which consumes the facts this pass extracts.
public enum Dissector {
    public enum LinkType {
        static let null: Int32 = 0            // BSD loopback, host byte order family
        static let ethernet: Int32 = 1
        static let rawBSD: Int32 = 12         // DLT_RAW on macOS (utun*)
        static let rawAlt: Int32 = 14
        static let ppp: Int32 = 9
        static let rawLinktype: Int32 = 101   // LINKTYPE_RAW in files
        static let ieee80211: Int32 = 105
        static let loop: Int32 = 108          // OpenBSD loopback, network byte order
        static let linuxSLL: Int32 = 113
        static let radiotap: Int32 = 127
        static let ipv4: Int32 = 228
        static let ipv6: Int32 = 229
        static let linuxSLL2: Int32 = 276
    }

    public static func dissect(_ raw: RawPacket, number: Int, validateChecksums: Bool = false) -> DissectionContext {
        let ctx = DissectionContext(data: raw.data, linkType: raw.linkType, validateChecksums: validateChecksums)
        frame(ctx, raw, number)
        switch raw.linkType {
        case LinkType.ethernet: ethernet(ctx, 0)
        case LinkType.null, LinkType.loop: loopback(ctx, raw.linkType == LinkType.loop)
        case LinkType.rawBSD, LinkType.rawAlt, LinkType.rawLinktype, LinkType.ipv4, LinkType.ipv6: rawIP(ctx, 0)
        case LinkType.linuxSLL: linuxSLL(ctx)
        case LinkType.linuxSLL2: linuxSLL2(ctx)
        case LinkType.radiotap: WLAN.radiotap(ctx)
        case LinkType.ieee80211: WLAN.frame(ctx, 0)
        case LinkType.ppp: ppp(ctx, 0)
        default:
            ctx.setInfo("Unsupported link type \(raw.linkType)")
            ctx.protocolName = "DLT \(raw.linkType)"
        }
        if raw.isTruncatedBySnaplen {
            ctx.flag(.note, .malformed, "Frame truncated by snaplen (\(raw.capturedLength)/\(raw.originalLength))")
        }
        return ctx
    }

    private static let timeFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = .current
        return f
    }()

    private static func frame(_ ctx: DissectionContext, _ raw: RawPacket, _ number: Int) {
        let date = Date(timeIntervalSince1970: raw.timestamp)
        let f = ctx.layer("frame", "Frame \(number): \(raw.originalLength) bytes on wire, \(raw.capturedLength) bytes captured",
                          0, raw.capturedLength)
        ctx.add(f, "Arrival Time: \(timeFormatter.string(from: date))",
                "frame.time_epoch", .int(Int64(raw.timestamp)), 0, 0)
        ctx.add(f, "Frame Number: \(number)", "frame.number", .int(Int64(number)), 0, 0)
        ctx.add(f, "Frame Length: \(raw.originalLength)", "frame.len", .int(Int64(raw.originalLength)), 0, 0)
        ctx.add(f, "Capture Length: \(raw.capturedLength)", "frame.cap_len", .int(Int64(raw.capturedLength)), 0, 0)
        ctx.add(f, "Link type: \(BPFValidator.linkTypeName(raw.linkType)) (\(raw.linkType))", "frame.dlt", .int(Int64(raw.linkType)), 0, 0)
        ctx.protocolName = ""
    }

    // MARK: - Link layers

    static func ethernet(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let dst = d.sub(o, 6), let src = d.sub(o + 6, 6), let type = d.be16(o + 12) else {
            ctx.malformed("Ethernet", ctx.layer("eth", "Ethernet", o, d.count - o))
            return
        }
        let node = ctx.layer("eth", "Ethernet II, Src: \(Fmt.mac(src)), Dst: \(Fmt.mac(dst))", o, 14)
        ctx.add(node, "Destination: \(Fmt.mac(dst))\(macNote(dst))", "eth.dst", .mac(dst), o, 6)
        ctx.add(node, "Source: \(Fmt.mac(src))", "eth.src", .mac(src), o + 6, 6)
        ctx.index("eth.addr", .mac(dst)); ctx.index("eth.addr", .mac(src))
        ctx.setAddresses(Fmt.mac(src), Fmt.mac(dst), network: false)
        if src[0] & 0x01 != 0 {
            ctx.flag(.warning, .malformed, "Source MAC is multicast/broadcast (invalid)", key: "eth.src_not_unicast", on: node)
        }
        if type <= 1500 {
            ctx.add(node, "Length: \(type)", "eth.len", .int(Int64(type)), o + 12, 2)
            llc(ctx, o + 14, dst: dst)
        } else {
            ctx.add(node, "Type: \(etherTypeName(type)) (\(Fmt.hex16(type)))", "eth.type", .int(Int64(type)), o + 12, 2)
            etherType(ctx, type, o + 14)
        }
    }

    private static func macNote(_ m: [UInt8]) -> String {
        if m.allSatisfy({ $0 == 0xFF }) { return " (Broadcast)" }
        if m[0] & 0x01 != 0 { return " (Multicast)" }
        return ""
    }

    static func loopback(_ ctx: DissectionContext, _ networkOrder: Bool) {
        let d = ctx.data
        guard let fam = networkOrder ? d.be32(0) : d.le32(0) else {
            ctx.malformed("Null/Loopback", ctx.layer("null", "Null/Loopback", 0, d.count)); return
        }
        // Family is in host order for DLT_NULL; captures from a big-endian host may show swapped values.
        let family = (fam > 0xFFFF) ? fam.byteSwapped : fam
        let node = ctx.layer("null", "Null/Loopback", 0, 4)
        ctx.add(node, "Family: \(family == 2 ? "IP" : (family == 24 || family == 28 || family == 30 ? "IPv6" : "\(family)")) (\(family))",
                "null.family", .int(Int64(family)), 0, 4)
        switch family {
        case 2: IP.v4(ctx, 4)
        case 24, 28, 30: IP.v6(ctx, 4)
        default: rawIP(ctx, 4)
        }
    }

    static func rawIP(_ ctx: DissectionContext, _ o: Int) {
        guard let v = ctx.data.u8(o) else { ctx.malformed("Raw IP", nil); return }
        switch v >> 4 {
        case 4: IP.v4(ctx, o)
        case 6: IP.v6(ctx, o)
        default:
            ctx.layer("data", "Raw packet data", o, ctx.data.count - o, display: "Raw")
            ctx.setInfo("Unknown IP version \(v >> 4)")
        }
    }

    static func linuxSLL(_ ctx: DissectionContext) {
        let d = ctx.data
        guard let ptype = d.be16(0), let alen = d.be16(4), let proto = d.be16(14) else {
            ctx.malformed("Linux SLL", ctx.layer("sll", "Linux cooked capture", 0, d.count)); return
        }
        let node = ctx.layer("sll", "Linux cooked capture v1", 0, 16)
        let types = ["Unicast to us", "Broadcast", "Multicast", "Unicast to another host", "Sent by us"]
        ctx.add(node, "Packet type: \(ptype < 5 ? types[Int(ptype)] : "\(ptype)")", "sll.pkttype", .int(Int64(ptype)), 0, 2)
        if let addr = d.sub(6, Int(min(alen, 8))) {
            ctx.add(node, "Source: \(Fmt.mac(addr))", "sll.src.eth", .mac(addr), 6, Int(min(alen, 8)))
            ctx.setAddresses(Fmt.mac(addr), "", network: false)
        }
        ctx.add(node, "Protocol: \(etherTypeName(proto)) (\(Fmt.hex16(proto)))", "sll.etype", .int(Int64(proto)), 14, 2)
        etherType(ctx, proto, 16)
    }

    static func linuxSLL2(_ ctx: DissectionContext) {
        let d = ctx.data
        guard let proto = d.be16(0), d.count >= 20 else {
            ctx.malformed("Linux SLL2", ctx.layer("sll", "Linux cooked capture v2", 0, d.count)); return
        }
        let node = ctx.layer("sll", "Linux cooked capture v2", 0, 20)
        ctx.add(node, "Protocol: \(etherTypeName(proto)) (\(Fmt.hex16(proto)))", "sll.etype", .int(Int64(proto)), 0, 2)
        if let idx = d.be32(4) { ctx.add(node, "Interface index: \(idx)", "sll.ifindex", .int(Int64(idx)), 4, 4) }
        etherType(ctx, proto, 20)
    }

    static func ppp(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        var off = o
        if d.u8(off) == 0xFF, d.u8(off + 1) == 0x03 { off += 2 }   // HDLC address/control
        guard let proto = d.be16(off) else { ctx.malformed("PPP", ctx.layer("ppp", "PPP", o, d.count - o)); return }
        let node = ctx.layer("ppp", "Point-to-Point Protocol", o, off + 2 - o)
        ctx.add(node, "Protocol: \(Fmt.hex16(proto))", "ppp.protocol", .int(Int64(proto)), off, 2)
        switch proto {
        case 0x0021: IP.v4(ctx, off + 2)
        case 0x0057: IP.v6(ctx, off + 2)
        case 0xC021: ctx.protocolName = "PPP LCP"; ctx.setInfo("Link Control Protocol")
        case 0xC023: ctx.protocolName = "PPP PAP"; ctx.setInfo("Password Authentication Protocol")
            ctx.flag(.warning, .security, "PAP sends credentials in cleartext", key: "ppp.pap.cleartext", on: node)
        case 0xC223: ctx.protocolName = "PPP CHAP"; ctx.setInfo("Challenge Handshake Authentication Protocol")
        case 0x8021: ctx.protocolName = "PPP IPCP"; ctx.setInfo("IP Control Protocol")
        default: ctx.setInfo("PPP protocol \(Fmt.hex16(proto))")
        }
    }

    // MARK: - EtherType demux

    static func etherType(_ ctx: DissectionContext, _ type: UInt16, _ o: Int) {
        switch type {
        case 0x0800: IP.v4(ctx, o)
        case 0x86DD: IP.v6(ctx, o)
        case 0x0806, 0x8035: L2.arp(ctx, o, reverse: type == 0x8035)
        case 0x8100, 0x88A8, 0x9100: L2.vlan(ctx, o, tpid: type)
        case 0x8847, 0x8848: L2.mpls(ctx, o)
        case 0x8863, 0x8864: L2.pppoe(ctx, o, session: type == 0x8864)
        case 0x88CC: L2.lldp(ctx, o)
        case 0x888E: L2.eapol(ctx, o)
        case 0x8809: L2.slow(ctx, o)
        case 0x88F7: L2.simple(ctx, "ptp", "PTPv2", "Precision Time Protocol (IEEE 1588)", o)
        case 0x88E5: L2.simple(ctx, "macsec", "MACsec", "IEEE 802.1AE MACsec", o)
        case 0x88A4: L2.simple(ctx, "ecat", "EtherCAT", "EtherCAT frame", o)
        case 0x8892: L2.simple(ctx, "pn_rt", "PROFINET", "PROFINET Real-Time", o)
        case 0x0842: L2.simple(ctx, "wol", "WOL", "Wake On LAN magic packet", o)
        case 0x88E1, 0x8912: L2.simple(ctx, "homeplug", "HomePlug", "HomePlug AV", o)
        case 0x22F3: L2.simple(ctx, "trill", "TRILL", "TRILL", o)
        case 0x894F: L2.simple(ctx, "nsh", "NSH", "Network Service Header", o)
        default:
            ctx.layer("data", "Data (\(max(0, ctx.data.count - o)) bytes)", o, ctx.data.count - o, display: "Ethernet")
            ctx.setInfo("Ethertype \(Fmt.hex16(type))")
        }
    }

    static func llc(_ ctx: DissectionContext, _ o: Int, dst: [UInt8]) {
        let d = ctx.data
        guard let dsap = d.u8(o), let ssap = d.u8(o + 1), let control = d.u8(o + 2) else {
            ctx.malformed("LLC", ctx.layer("llc", "Logical-Link Control", o, d.count - o)); return
        }
        let node = ctx.layer("llc", "Logical-Link Control", o, 3)
        ctx.add(node, "DSAP: \(Fmt.hex8(dsap))", "llc.dsap", .int(Int64(dsap)), o, 1)
        ctx.add(node, "SSAP: \(Fmt.hex8(ssap))", "llc.ssap", .int(Int64(ssap)), o + 1, 1)
        ctx.add(node, "Control: \(Fmt.hex8(control))", "llc.control", .int(Int64(control)), o + 2, 1)
        if dsap == 0x42, ssap == 0x42 { L2.stp(ctx, o + 3); return }
        if dsap == 0xFE, ssap == 0xFE { L2.simple(ctx, "isis", "IS-IS", "IS-IS / OSI", o + 3); return }
        if dsap == 0xAA, ssap == 0xAA, let oui = d.be24(o + 3), let pid = d.be16(o + 6) {
            ctx.add(node, "SNAP OUI: \(String(format: "%06x", oui)), PID: \(Fmt.hex16(pid))", "llc.pid", .int(Int64(pid)), o + 3, 5)
            if oui == 0x00000C {
                switch pid {
                case 0x2000: L2.cdp(ctx, o + 8)
                case 0x2004: L2.simple(ctx, "dtp", "DTP", "Dynamic Trunking Protocol", o + 8)
                case 0x2003: L2.simple(ctx, "vtp", "VTP", "VLAN Trunking Protocol", o + 8)
                case 0x010B: L2.simple(ctx, "pvst", "PVST+", "Cisco PVST+ BPDU", o + 8)
                default: ctx.setInfo("Cisco SNAP PID \(Fmt.hex16(pid))")
                }
            } else if oui == 0 {
                etherType(ctx, pid, o + 8)
            }
            return
        }
        ctx.protocolName = "LLC"
        ctx.setInfo("DSAP \(Fmt.hex8(dsap)) SSAP \(Fmt.hex8(ssap))")
    }

    public static func etherTypeName(_ t: UInt16) -> String {
        switch t {
        case 0x0800: "IPv4"
        case 0x86DD: "IPv6"
        case 0x0806: "ARP"
        case 0x8035: "RARP"
        case 0x8100: "802.1Q VLAN"
        case 0x88A8: "802.1ad"
        case 0x8847: "MPLS unicast"
        case 0x8848: "MPLS multicast"
        case 0x8863: "PPPoE Discovery"
        case 0x8864: "PPPoE Session"
        case 0x88CC: "LLDP"
        case 0x888E: "802.1X"
        case 0x8809: "Slow Protocols"
        case 0x88F7: "PTP"
        case 0x88E5: "MACsec"
        default: "Unknown"
        }
    }
}
