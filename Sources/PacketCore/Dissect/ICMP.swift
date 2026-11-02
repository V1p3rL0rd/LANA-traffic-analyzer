import Foundation

enum ICMP {
    static let unreachCodes = [
        0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable", 3: "Port unreachable",
        4: "Fragmentation needed and DF set", 5: "Source route failed", 6: "Destination network unknown",
        7: "Destination host unknown", 9: "Network administratively prohibited", 10: "Host administratively prohibited",
        13: "Communication administratively filtered",
    ]

    static func v4(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let type = d.u8(o), let code = d.u8(o + 1), let csum = d.be16(o + 2) else {
            ctx.malformed("ICMP", ctx.layer("icmp", "Internet Control Message Protocol", o, end - o, display: "ICMP")); return
        }
        let node = ctx.layer("icmp", "Internet Control Message Protocol", o, end - o, display: "ICMP")
        ctx.add(node, "Type: \(type)", "icmp.type", .int(Int64(type)), o, 1)
        ctx.add(node, "Code: \(code)", "icmp.code", .int(Int64(code)), o + 1, 1)
        let cs = ctx.add(node, "Checksum: \(Fmt.hex16(csum))", "icmp.checksum", .int(Int64(csum)), o + 2, 2)
        if ctx.validateChecksums, Checksum.fold(Checksum.sum(d, o ..< end)) != 0 {
            ctx.flag(.error, .checksum, "Bad ICMP checksum", key: "icmp.checksum.bad", on: cs)
        }
        let ident = d.be16(o + 4) ?? 0, seq = d.be16(o + 6) ?? 0

        switch type {
        case 0, 8:
            ctx.add(node, "Identifier: \(Fmt.hex16(ident))", "icmp.ident", .int(Int64(ident)), o + 4, 2)
            ctx.add(node, "Sequence Number: \(seq)", "icmp.seq", .int(Int64(seq)), o + 6, 2)
            ctx.setInfo("Echo (ping) \(type == 8 ? "request" : "reply")  id=\(Fmt.hex16(ident)), seq=\(seq)")
            if end - o > 1024 {
                ctx.flag(.warning, .security, "Oversized ICMP echo (\(end - o) bytes) — possible tunnel/exfiltration",
                         key: "icmp.oversized", on: node)
            }
        case 3:
            let reason = unreachCodes[Int(code)] ?? "Code \(code)"
            ctx.setInfo("Destination unreachable (\(reason))")
            if code == 4, let mtu = d.be16(o + 6) {
                ctx.add(node, "Next-hop MTU: \(mtu)", "icmp.mtu", .int(Int64(mtu)), o + 6, 2)
                ctx.flag(.warning, .performance, "PMTU discovery: fragmentation needed (MTU \(mtu))", key: "icmp.frag_needed", on: node)
            } else {
                ctx.flag(.error, .response, "Destination unreachable: \(reason)", key: "icmp.unreachable", on: node)
            }
            embedded(ctx, node, o + 8, end)
        case 11:
            ctx.setInfo("Time-to-live exceeded (\(code == 0 ? "in transit" : "fragment reassembly"))")
            ctx.flag(.warning, .response, "TTL exceeded \(code == 0 ? "in transit" : "during reassembly")", key: "icmp.ttl_exceeded", on: node)
            embedded(ctx, node, o + 8, end)
        case 5:
            let gw = d.be32(o + 4).map(Fmt.ipv4) ?? "?"
            ctx.setInfo("Redirect (gateway \(gw))")
            ctx.flag(.warning, .security, "ICMP redirect to \(gw) — verify (MITM vector)", key: "icmp.redirect", on: node)
            embedded(ctx, node, o + 8, end)
        case 4:
            ctx.setInfo("Source quench (deprecated)")
            ctx.flag(.warning, .performance, "Source quench", on: node)
        case 12:
            ctx.setInfo("Parameter problem")
            ctx.flag(.error, .protocolError, "ICMP parameter problem", key: "icmp.param_problem", on: node)
            embedded(ctx, node, o + 8, end)
        case 13, 14: ctx.setInfo("Timestamp \(type == 13 ? "request" : "reply")")
        case 9, 10: ctx.setInfo("Router \(type == 9 ? "advertisement" : "solicitation")")
        default: ctx.setInfo("ICMP type \(type) code \(code)")
        }
    }

    /// Shows the offending header quoted in ICMP errors.
    private static func embedded(_ ctx: DissectionContext, _ node: Field, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let vihl = d.u8(o), vihl >> 4 == 4, let src = d.be32(o + 12), let dst = d.be32(o + 16), let proto = d.u8(o + 9) else { return }
        let ihl = Int(vihl & 0xF) * 4
        var text = "Original: \(Fmt.ipv4(src)) → \(Fmt.ipv4(dst)) \(IP.protoNames[proto] ?? String(proto))"
        if proto == 6 || proto == 17, let sp = d.be16(o + ihl), let dp = d.be16(o + ihl + 2) {
            text += " \(sp) → \(dp)"
            ctx.index(proto == 6 ? "icmp.tcp.port" : "icmp.udp.port", .int(Int64(dp)))
        }
        ctx.add(node, text, "icmp.inner.dst", .ipv4(dst), o, end - o)
        ctx.info += "  [\(text)]"
    }

    static func v6(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let type = d.u8(o), let code = d.u8(o + 1) else {
            ctx.malformed("ICMPv6", ctx.layer("icmpv6", "Internet Control Message Protocol v6", o, end - o, display: "ICMPv6")); return
        }
        let node = ctx.layer("icmpv6", "Internet Control Message Protocol v6", o, end - o, display: "ICMPv6")
        ctx.add(node, "Type: \(type)", "icmpv6.type", .int(Int64(type)), o, 1)
        ctx.add(node, "Code: \(code)", "icmpv6.code", .int(Int64(code)), o + 1, 1)
        func target(_ at: Int) -> String {
            guard let t = d.sub(at, 16) else { return "?" }
            ctx.add(node, "Target Address: \(Fmt.ipv6(t))", "icmpv6.nd.ns.target_address", .ipv6(t), at, 16)
            return Fmt.ipv6(t)
        }
        switch type {
        case 1:
            let r = ["No route", "Administratively prohibited", "Beyond scope", "Address unreachable", "Port unreachable",
                     "Source address failed policy", "Reject route"]
            let reason = Int(code) < r.count ? r[Int(code)] : "code \(code)"
            ctx.setInfo("Destination Unreachable (\(reason))")
            ctx.flag(.error, .response, "ICMPv6 destination unreachable: \(reason)", key: "icmpv6.unreachable", on: node)
        case 2:
            let mtu = d.be32(o + 4) ?? 0
            ctx.setInfo("Packet Too Big (MTU \(mtu))")
            ctx.flag(.warning, .performance, "Packet too big, MTU \(mtu)", key: "icmpv6.too_big", on: node)
        case 3:
            ctx.setInfo("Time Exceeded")
            ctx.flag(.warning, .response, "Hop limit exceeded", key: "icmpv6.time_exceeded", on: node)
        case 4:
            ctx.setInfo("Parameter Problem")
            ctx.flag(.error, .protocolError, "ICMPv6 parameter problem", key: "icmpv6.param_problem", on: node)
        case 128, 129:
            let id = d.be16(o + 4) ?? 0, seq = d.be16(o + 6) ?? 0
            ctx.setInfo("Echo (ping) \(type == 128 ? "request" : "reply") id=\(Fmt.hex16(id)), seq=\(seq)")
        case 130, 131, 132, 143:
            ctx.setInfo(type == 143 ? "Multicast Listener Report Message v2" : "Multicast Listener \(type == 130 ? "Query" : type == 131 ? "Report" : "Done")")
        case 133: ctx.setInfo("Router Solicitation")
        case 134:
            let lifetime = d.be16(o + 6) ?? 0
            ctx.setInfo("Router Advertisement (lifetime \(lifetime)s)")
            ctx.flag(.note, .security, "Router Advertisement — verify the router is legitimate (RA guard)", key: "icmpv6.ra", on: node)
        case 135: ctx.setInfo("Neighbor Solicitation for \(target(o + 8))")
        case 136:
            let flags = d.u8(o + 4) ?? 0
            ctx.setInfo("Neighbor Advertisement \(target(o + 8))\(flags & 0x80 != 0 ? " (rtr" : " (")\(flags & 0x40 != 0 ? ", sol" : "")\(flags & 0x20 != 0 ? ", ovr" : ""))")
        case 137:
            ctx.setInfo("Redirect")
            ctx.flag(.warning, .security, "ICMPv6 redirect — verify (MITM vector)", key: "icmpv6.redirect", on: node)
        default: ctx.setInfo("ICMPv6 type \(type) code \(code)")
        }
    }

    static func igmp(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let type = d.u8(o) else { ctx.malformed("IGMP", ctx.layer("igmp", "IGMP", o, end - o)); return }
        let node = ctx.layer("igmp", "Internet Group Management Protocol", o, end - o, display: "IGMP")
        ctx.add(node, "Type: \(Fmt.hex8(type))", "igmp.type", .int(Int64(type)), o, 1)
        let group = d.be32(o + 4).map(Fmt.ipv4) ?? "?"
        switch type {
        case 0x11: ctx.setInfo(group == "0.0.0.0" ? "Membership Query, general" : "Membership Query, specific for group \(group)")
        case 0x12, 0x16: ctx.setInfo("Membership Report group \(group)")
        case 0x17: ctx.setInfo("Leave Group \(group)")
        case 0x22: ctx.setInfo("Membership Report v3 (\(d.be16(o + 6) ?? 0) records)")
        default: ctx.setInfo("IGMP type \(Fmt.hex8(type))")
        }
    }
}

enum Routing {
    static func simple(_ ctx: DissectionContext, _ abbrev: String, _ name: String, _ title: String, _ o: Int, _ end: Int) {
        ctx.layer(abbrev, title, o, end - o, display: name)
        ctx.setInfo(title)
    }

    static func ospf(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let ver = d.u8(o), let type = d.u8(o + 1), let rid = d.be32(o + 4), let area = d.be32(o + 8) else {
            ctx.malformed("OSPF", ctx.layer("ospf", "Open Shortest Path First", o, end - o, display: "OSPF")); return
        }
        let types = [1: "Hello Packet", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Acknowledge"]
        let node = ctx.layer("ospf", "Open Shortest Path First v\(ver)", o, end - o, display: "OSPF")
        ctx.add(node, "Message Type: \(types[Int(type)] ?? "?") (\(type))", "ospf.msg", .int(Int64(type)), o + 1, 1)
        ctx.add(node, "Source OSPF Router: \(Fmt.ipv4(rid))", "ospf.srcrouter", .ipv4(rid), o + 4, 4)
        ctx.add(node, "Area ID: \(Fmt.ipv4(area))", "ospf.area_id", .ipv4(area), o + 8, 4)
        if ver == 2, let auType = d.be16(o + 14) {
            ctx.add(node, "Auth Type: \(auType == 0 ? "Null" : auType == 1 ? "Simple password" : "Cryptographic")",
                    "ospf.auth.type", .int(Int64(auType)), o + 14, 2)
            if auType == 1 { ctx.flag(.warning, .security, "OSPF simple (cleartext) password authentication", key: "ospf.auth.cleartext", on: node) }
        }
        ctx.setInfo(types[Int(type)] ?? "OSPF type \(type)")
    }

    static func vrrp(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let vt = d.u8(o), let vrid = d.u8(o + 1), let prio = d.u8(o + 2) else {
            ctx.malformed("VRRP", ctx.layer("vrrp", "Virtual Router Redundancy Protocol", o, end - o, display: "VRRP")); return
        }
        let node = ctx.layer("vrrp", "Virtual Router Redundancy Protocol v\(vt >> 4)", o, end - o, display: "VRRP")
        ctx.add(node, "Virtual Rtr ID: \(vrid)", "vrrp.virt_rtr_id", .int(Int64(vrid)), o + 1, 1)
        ctx.add(node, "Priority: \(prio)", "vrrp.prio", .int(Int64(prio)), o + 2, 1)
        ctx.setInfo("Announcement (v\(vt >> 4)) VRID \(vrid) prio \(prio)")
        if prio == 0 { ctx.flag(.warning, .protocolError, "VRRP master is resigning (priority 0) — failover", key: "vrrp.resign", on: node) }
    }
}
