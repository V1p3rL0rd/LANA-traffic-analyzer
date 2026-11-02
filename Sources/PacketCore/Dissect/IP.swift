import Foundation

/// Addressing context passed from L3 to L4 (also used for pseudo-header checksums).
struct IPInfo {
    let version: Int
    let src: String
    let dst: String
    let srcBytes: [UInt8]
    let dstBytes: [UInt8]
    let dstIsMulticast: Bool

    func pseudoHeaderSum(proto: UInt8, length: Int) -> UInt32 {
        var s = Checksum.sum(srcBytes, 0 ..< srcBytes.count)
        s = Checksum.sum(dstBytes, 0 ..< dstBytes.count, initial: s)
        if version == 4 {
            s &+= UInt32(proto) &+ UInt32(length)
        } else {
            s &+= UInt32(length >> 16) &+ UInt32(length & 0xFFFF) &+ UInt32(proto)
        }
        return s
    }
}

enum IP {
    static let protoNames: [UInt8: String] = [
        0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 33: "DCCP", 41: "IPv6", 43: "IPv6-Route",
        44: "IPv6-Frag", 46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
        88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLite", 137: "MPLS-in-IP",
    ]

    // MARK: IPv4

    static func v4(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let vihl = d.u8(o), let tos = d.u8(o + 1), let totalLen = d.be16(o + 2), let ident = d.be16(o + 4),
              let fragField = d.be16(o + 6), let ttl = d.u8(o + 8), let proto = d.u8(o + 9), let csum = d.be16(o + 10),
              let srcV = d.be32(o + 12), let dstV = d.be32(o + 16) else {
            ctx.malformed("IPv4", ctx.layer("ip", "Internet Protocol Version 4", o, d.count - o, display: "IPv4")); return
        }
        let ihl = Int(vihl & 0x0F) * 4
        let src = Fmt.ipv4(srcV), dst = Fmt.ipv4(dstV)
        let node = ctx.layer("ip", "Internet Protocol Version 4, Src: \(src), Dst: \(dst)", o, max(ihl, 20), display: "IPv4")
        ctx.setAddresses(src, dst, network: true)

        ctx.add(node, "Version: \(vihl >> 4)", "ip.version", .int(Int64(vihl >> 4)), o, 1)
        ctx.add(node, "Header Length: \(ihl) bytes", "ip.hdr_len", .int(Int64(ihl)), o, 1)
        ctx.add(node, "DSCP: \(tos >> 2), ECN: \(tos & 3)", "ip.dsfield.dscp", .int(Int64(tos >> 2)), o + 1, 1)
        ctx.add(node, "Total Length: \(totalLen)", "ip.len", .int(Int64(totalLen)), o + 2, 2)
        ctx.add(node, "Identification: \(Fmt.hex16(ident)) (\(ident))", "ip.id", .int(Int64(ident)), o + 4, 2)
        let rb = fragField & 0x8000 != 0, df = fragField & 0x4000 != 0, mf = fragField & 0x2000 != 0
        let fragOffset = Int(fragField & 0x1FFF) * 8
        let flags = ctx.add(node, "Flags: \(df ? "Don't fragment" : "")\(mf ? "More fragments" : "")\(rb ? " Reserved" : "")",
                            "ip.flags", .int(Int64(fragField >> 13)), o + 6, 2)
        ctx.index("ip.flags.df", .bool(df)); ctx.index("ip.flags.mf", .bool(mf))
        ctx.add(node, "Fragment Offset: \(fragOffset)", "ip.frag_offset", .int(Int64(fragOffset)), o + 6, 2)
        let ttlNode = ctx.add(node, "Time to Live: \(ttl)", "ip.ttl", .int(Int64(ttl)), o + 8, 1)
        ctx.add(node, "Protocol: \(protoNames[proto] ?? "Unknown") (\(proto))", "ip.proto", .int(Int64(proto)), o + 9, 1)
        let csNode = ctx.add(node, "Header Checksum: \(Fmt.hex16(csum))", "ip.checksum", .int(Int64(csum)), o + 10, 2)
        ctx.add(node, "Source Address: \(src)", "ip.src", .ipv4(srcV), o + 12, 4)
        ctx.add(node, "Destination Address: \(dst)", "ip.dst", .ipv4(dstV), o + 16, 4)
        ctx.index("ip.addr", .ipv4(srcV)); ctx.index("ip.addr", .ipv4(dstV))
        ctx.index("ip.host", .string(src)); ctx.index("ip.host", .string(dst))

        // --- sanity / anomaly checks ---
        guard vihl >> 4 == 4 else { ctx.malformed("IPv4", node, "version field is \(vihl >> 4)"); return }
        guard ihl >= 20 else { ctx.malformed("IPv4", node, "header length \(ihl) < 20"); return }
        guard Int(totalLen) >= ihl else { ctx.malformed("IPv4", node, "total length \(totalLen) < header length"); return }
        if ihl > 20 {
            ctx.add(node, "Options: (\(ihl - 20) bytes)", "ip.opt", .bool(true), o + 20, ihl - 20)
            ctx.flag(.note, .protocolError, "IPv4 options present", key: "ip.options", on: node)
        }
        let isMcast = (dstV >> 28) == 0xE
        let isBcast = dstV == 0xFFFF_FFFF
        if (srcV >> 28) == 0xE || srcV == 0xFFFF_FFFF {
            ctx.flag(.error, .malformed, "Source address is multicast/broadcast", key: "ip.src_invalid", on: node)
        }
        if srcV == dstV, srcV != 0, (srcV >> 24) != 127 {
            ctx.flag(.error, .security, "Source equals destination (LAND attack pattern)", key: "ip.land", on: node)
        }
        if rb { ctx.flag(.warning, .malformed, "Reserved (evil) bit set", key: "ip.flags.rb", on: flags) }
        if ttl == 0 {
            ctx.flag(.error, .protocolError, "TTL is zero", key: "ip.ttl.zero", on: ttlNode)
        } else if ttl == 1, !isMcast, !isBcast, proto != 2 {
            ctx.flag(.warning, .protocolError, "TTL 1 for unicast (traceroute or routing loop?)", key: "ip.ttl.too_small", on: ttlNode)
        }
        if ctx.validateChecksums, d.count >= o + ihl {
            let computed = Checksum.fold(Checksum.sum(d, o ..< o + ihl))
            if computed != 0 {
                csNode.label += " [incorrect]"
                ctx.flag(.error, .checksum, "Bad IPv4 header checksum", key: "ip.checksum.bad", on: csNode)
            } else { csNode.label += " [correct]" }
        }
        // Clamp to the IP total length: strips Ethernet padding, tolerates snaplen truncation.
        let end = min(d.count, o + Int(totalLen))

        let info = IPInfo(version: 4, src: src, dst: dst, srcBytes: d.sub(o + 12, 4)!, dstBytes: d.sub(o + 16, 4)!,
                          dstIsMulticast: isMcast || isBcast)
        if mf || fragOffset > 0 {
            ctx.flag(.warning, .protocolError, "Fragmented IPv4 packet (offset \(fragOffset)\(mf ? ", more" : ""))",
                     key: "ip.fragment", on: node)
            if fragOffset > 0 {
                ctx.layer("data", "Fragment data (\(end - o - ihl) bytes)", o + ihl, end - o - ihl, display: "IPv4")
                ctx.setInfo("Fragmented IP protocol (proto=\(protoNames[proto] ?? String(proto)) \(proto), off=\(fragOffset), ID=\(Fmt.hex16(ident)))")
                return
            }
            // Tiny first fragment that cannot hold the L4 header: classic IDS evasion.
            if end - (o + ihl) < 8 {
                ctx.flag(.error, .security, "Tiny first fragment (overlap/evasion pattern)", key: "ip.fragment.tiny", on: node)
            }
        }
        payload(ctx, proto, o + ihl, end, info)
    }

    // MARK: IPv6

    static func v6(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let vtf = d.be32(o), let plen = d.be16(o + 4), let nh = d.u8(o + 6), let hlim = d.u8(o + 7),
              let srcB = d.sub(o + 8, 16), let dstB = d.sub(o + 24, 16) else {
            ctx.malformed("IPv6", ctx.layer("ipv6", "Internet Protocol Version 6", o, d.count - o, display: "IPv6")); return
        }
        let src = Fmt.ipv6(srcB), dst = Fmt.ipv6(dstB)
        let node = ctx.layer("ipv6", "Internet Protocol Version 6, Src: \(src), Dst: \(dst)", o, 40, display: "IPv6")
        ctx.setAddresses(src, dst, network: true)
        ctx.add(node, "Version: \(vtf >> 28)", "ipv6.version", .int(Int64(vtf >> 28)), o, 1)
        ctx.add(node, "Traffic Class: \(Fmt.hex8(UInt8((vtf >> 20) & 0xFF)))", "ipv6.tclass", .int(Int64((vtf >> 20) & 0xFF)), o, 2)
        ctx.add(node, "Flow Label: \(String(format: "0x%05x", vtf & 0xFFFFF))", "ipv6.flow", .int(Int64(vtf & 0xFFFFF)), o + 1, 3)
        ctx.add(node, "Payload Length: \(plen)", "ipv6.plen", .int(Int64(plen)), o + 4, 2)
        ctx.add(node, "Next Header: \(protoNames[nh] ?? "?") (\(nh))", "ipv6.nxt", .int(Int64(nh)), o + 6, 1)
        let hl = ctx.add(node, "Hop Limit: \(hlim)", "ipv6.hlim", .int(Int64(hlim)), o + 7, 1)
        ctx.add(node, "Source Address: \(src)", "ipv6.src", .ipv6(srcB), o + 8, 16)
        ctx.add(node, "Destination Address: \(dst)", "ipv6.dst", .ipv6(dstB), o + 24, 16)
        ctx.index("ipv6.addr", .ipv6(srcB)); ctx.index("ipv6.addr", .ipv6(dstB))

        let mcast = dstB[0] == 0xFF
        if srcB[0] == 0xFF { ctx.flag(.error, .malformed, "Source address is multicast", key: "ipv6.src_invalid", on: node) }
        if hlim == 0 {
            ctx.flag(.error, .protocolError, "Hop limit is zero", key: "ipv6.hlim.zero", on: hl)
        } else if hlim == 1, !mcast {
            ctx.flag(.warning, .protocolError, "Hop limit 1 for unicast", key: "ipv6.hlim.too_small", on: hl)
        }
        let end = min(d.count, o + 40 + Int(plen))
        if plen == 0, nh != 59 {
            ctx.flag(.note, .protocolError, "Payload length 0 (jumbogram?)", on: node)
        }

        // Extension header chain.
        var next = nh, off = o + 40, guardCount = 0
        while [0, 43, 44, 60].contains(next), guardCount < 10 {
            guardCount += 1
            guard let nxt = d.u8(off), let hlen = d.u8(off + 1) else { ctx.malformed("IPv6", node, "truncated extension header"); return }
            let len = next == 44 ? 8 : (Int(hlen) + 1) * 8
            switch next {
            case 0: ctx.add(node, "Hop-by-Hop Options (\(len) bytes)", "ipv6.hopopts", .bool(true), off, len)
            case 60: ctx.add(node, "Destination Options (\(len) bytes)", "ipv6.dstopts", .bool(true), off, len)
            case 43:
                let rtype = d.u8(off + 2) ?? 255
                let r = ctx.add(node, "Routing Header, Type \(rtype)", "ipv6.routing.type", .int(Int64(rtype)), off, len)
                if rtype == 0 {
                    ctx.flag(.error, .security, "Deprecated Type 0 Routing Header (RFC 5095)", key: "ipv6.routing.rh0", on: r)
                }
            case 44:
                let fo = (d.be16(off + 2) ?? 0)
                let foff = Int(fo >> 3) * 8, more = fo & 1 == 1
                let f = ctx.add(node, "Fragment Header: offset \(foff)\(more ? ", more" : "")", "ipv6.fragment", .bool(true), off, 8)
                ctx.flag(.warning, .protocolError, "Fragmented IPv6 packet", key: "ipv6.fragment", on: f)
                if foff > 0 {
                    ctx.setInfo("IPv6 fragment (off=\(foff), next=\(protoNames[nxt] ?? String(nxt)))")
                    return
                }
            default: break
            }
            next = nxt
            off += len
        }
        ctx.index("ipv6.nxt_final", .int(Int64(next)))
        let info = IPInfo(version: 6, src: src, dst: dst, srcBytes: srcB, dstBytes: dstB, dstIsMulticast: mcast)
        payload(ctx, next, off, end, info)
    }

    // MARK: L4 demux

    static func payload(_ ctx: DissectionContext, _ proto: UInt8, _ o: Int, _ end: Int, _ ip: IPInfo) {
        ctx.encapsulationDepth += 1
        guard ctx.encapsulationDepth < 12 else { ctx.malformed("IP", nil, "encapsulation too deep"); return }
        switch proto {
        case 6: Transport.tcp(ctx, o, end, ip)
        case 17: Transport.udp(ctx, o, end, ip)
        case 132: Transport.sctp(ctx, o, end)
        case 1: ICMP.v4(ctx, o, end)
        case 58: ICMP.v6(ctx, o, end)
        case 2: ICMP.igmp(ctx, o, end)
        case 4: v4(ctx, o)
        case 41: v6(ctx, o)
        case 47: gre(ctx, o, end)
        case 50: esp(ctx, o, end)
        case 51: ah(ctx, o, end, ip)
        case 89: Routing.ospf(ctx, o, end)
        case 112: Routing.vrrp(ctx, o, end)
        case 103: Routing.simple(ctx, "pim", "PIM", "Protocol Independent Multicast", o, end)
        case 88: Routing.simple(ctx, "eigrp", "EIGRP", "Enhanced Interior Gateway Routing Protocol", o, end)
        case 46: Routing.simple(ctx, "rsvp", "RSVP", "Resource ReSerVation Protocol", o, end)
        case 115: Routing.simple(ctx, "l2tp", "L2TPv3", "Layer 2 Tunneling Protocol v3", o, end)
        case 59: ctx.setInfo("IPv6 no next header")
        default:
            ctx.layer("data", "Data (\(max(0, end - o)) bytes)", o, end - o, display: protoNames[proto] ?? "IP proto \(proto)")
            ctx.setInfo("IP protocol \(proto)")
        }
    }

    static func gre(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let flags = d.be16(o), let ptype = d.be16(o + 2) else {
            ctx.malformed("GRE", ctx.layer("gre", "Generic Routing Encapsulation", o, end - o)); return
        }
        let ver = flags & 0x7
        var off = o + 4
        let node = ctx.layer("gre", "Generic Routing Encapsulation (\(Dissector.etherTypeName(ptype)))", o, 4, display: "GRE")
        ctx.add(node, "Flags and Version: \(Fmt.hex16(flags))", "gre.flags_and_version", .int(Int64(flags)), o, 2)
        ctx.add(node, "Protocol Type: \(Fmt.hex16(ptype))", "gre.proto", .int(Int64(ptype)), o + 2, 2)
        if flags & 0x8000 != 0 { ctx.add(node, "Checksum present", nil, nil, off, 4); off += 4 }
        if flags & 0x2000 != 0, let key = d.be32(off) {
            ctx.add(node, "Key: \(Fmt.hex32(key))", "gre.key", .int(Int64(key)), off, 4); off += 4
        }
        if flags & 0x1000 != 0, let seq = d.be32(off) {
            ctx.add(node, "Sequence Number: \(seq)", "gre.sequence_number", .int(Int64(seq)), off, 4); off += 4
        }
        if ver == 1 { // Enhanced GRE (PPTP)
            if flags & 0x0080 != 0 { off += 4 }
            if off < end { Dissector.ppp(ctx, off) } else { ctx.setInfo("PPTP GRE ack") }
            return
        }
        if ptype == 0x6558 { Dissector.ethernet(ctx, off) }      // Transparent Ethernet bridging
        else if ptype == 0x88BE || ptype == 0x22EB { ctx.setInfo("ERSPAN") }
        else { Dissector.etherType(ctx, ptype, off) }
    }

    static func esp(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let spi = d.be32(o), let seq = d.be32(o + 4) else {
            ctx.malformed("ESP", ctx.layer("esp", "Encapsulating Security Payload", o, end - o)); return
        }
        let node = ctx.layer("esp", "Encapsulating Security Payload", o, end - o, display: "ESP")
        ctx.add(node, "SPI: \(Fmt.hex32(spi))", "esp.spi", .int(Int64(spi)), o, 4)
        ctx.add(node, "Sequence: \(seq)", "esp.sequence", .int(Int64(seq)), o + 4, 4)
        ctx.setInfo("ESP (SPI=\(Fmt.hex32(spi)))")
    }

    static func ah(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ ip: IPInfo) {
        let d = ctx.data
        guard let nh = d.u8(o), let len = d.u8(o + 1), let spi = d.be32(o + 4), let seq = d.be32(o + 8) else {
            ctx.malformed("AH", ctx.layer("ah", "Authentication Header", o, end - o)); return
        }
        let hlen = (Int(len) + 2) * 4
        let node = ctx.layer("ah", "Authentication Header", o, hlen, display: "AH")
        ctx.add(node, "Next header: \(protoNames[nh] ?? String(nh))", "ah.nxt", .int(Int64(nh)), o, 1)
        ctx.add(node, "SPI: \(Fmt.hex32(spi))", "ah.spi", .int(Int64(spi)), o + 4, 4)
        ctx.add(node, "Sequence: \(seq)", "ah.sequence", .int(Int64(seq)), o + 8, 4)
        payload(ctx, nh, o + hlen, end, ip)
    }
}
