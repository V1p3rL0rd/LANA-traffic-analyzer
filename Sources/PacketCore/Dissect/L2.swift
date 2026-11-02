import Foundation

enum L2 {
    static func simple(_ ctx: DissectionContext, _ abbrev: String, _ name: String, _ title: String, _ o: Int) {
        ctx.layer(abbrev, title, o, ctx.data.count - o, display: name)
        ctx.setInfo(title)
    }

    static func arp(_ ctx: DissectionContext, _ o: Int, reverse: Bool) {
        let d = ctx.data
        let name = reverse ? "RARP" : "ARP"
        guard let htype = d.be16(o), let ptype = d.be16(o + 2), let hlen = d.u8(o + 4), let plen = d.u8(o + 5),
              let op = d.be16(o + 6) else {
            ctx.malformed(name, ctx.layer(name.lowercased(), name, o, d.count - o)); return
        }
        let h = Int(hlen), p = Int(plen)
        let node = ctx.layer(name.lowercased(), "Address Resolution Protocol", o, 8 + 2 * (h + p), display: name)
        let ops = [1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"]
        ctx.add(node, "Hardware type: \(htype == 1 ? "Ethernet" : String(htype)) (\(htype))", "arp.hw.type", .int(Int64(htype)), o, 2)
        ctx.add(node, "Protocol type: \(Fmt.hex16(ptype))", "arp.proto.type", .int(Int64(ptype)), o + 2, 2)
        ctx.add(node, "Opcode: \(ops[Int(op)] ?? "unknown") (\(op))", "arp.opcode", .int(Int64(op)), o + 6, 2)
        guard h == 6, p == 4, let sha = d.sub(o + 8, 6), let spa = d.be32(o + 14),
              let tha = d.sub(o + 18, 6), let tpa = d.be32(o + 24) else {
            if h != 6 || p != 4 { ctx.setInfo("\(name) htype=\(htype) ptype=\(Fmt.hex16(ptype))") } else { ctx.malformed(name, node) }
            return
        }
        ctx.add(node, "Sender MAC: \(Fmt.mac(sha))", "arp.src.hw_mac", .mac(sha), o + 8, 6)
        ctx.add(node, "Sender IP: \(Fmt.ipv4(spa))", "arp.src.proto_ipv4", .ipv4(spa), o + 14, 4)
        ctx.add(node, "Target MAC: \(Fmt.mac(tha))", "arp.dst.hw_mac", .mac(tha), o + 18, 6)
        ctx.add(node, "Target IP: \(Fmt.ipv4(tpa))", "arp.dst.proto_ipv4", .ipv4(tpa), o + 24, 4)
        ctx.arp = ARPFacts(opcode: op, senderMAC: sha, senderIP: spa, targetIP: tpa)

        switch op {
        case 1 where spa == tpa:
            ctx.setInfo("Gratuitous ARP for \(Fmt.ipv4(spa)) (Request)")
            ctx.flag(.note, .protocolError, "Gratuitous ARP", key: "arp.isgratuitous", on: node)
        case 1 where spa == 0:
            ctx.setInfo("Who has \(Fmt.ipv4(tpa))? (ARP Probe)")
        case 1:
            ctx.setInfo("Who has \(Fmt.ipv4(tpa))? Tell \(Fmt.ipv4(spa))")
        case 2:
            ctx.setInfo("\(Fmt.ipv4(spa)) is at \(Fmt.mac(sha))")
            if spa == tpa {
                ctx.flag(.warning, .security, "Unsolicited (gratuitous) ARP reply — typical for ARP spoofing", key: "arp.isgratuitous", on: node)
            }
        default:
            ctx.setInfo("\(name) opcode \(op)")
        }
    }

    static func vlan(_ ctx: DissectionContext, _ o: Int, tpid: UInt16) {
        let d = ctx.data
        guard let tci = d.be16(o), let type = d.be16(o + 2) else {
            ctx.malformed("802.1Q", ctx.layer("vlan", "802.1Q Virtual LAN", o, d.count - o)); return
        }
        let id = tci & 0x0FFF, pcp = tci >> 13, dei = (tci >> 12) & 1
        let node = ctx.layer("vlan", "802.1\(tpid == 0x8100 ? "Q" : "ad") Virtual LAN, PRI: \(pcp), DEI: \(dei), ID: \(id)", o, 4, display: "VLAN")
        ctx.add(node, "Priority: \(pcp)", "vlan.priority", .int(Int64(pcp)), o, 2)
        ctx.add(node, "DEI: \(dei)", "vlan.dei", .int(Int64(dei)), o, 2)
        ctx.add(node, "ID: \(id)", "vlan.id", .int(Int64(id)), o, 2)
        ctx.add(node, "Type: \(Dissector.etherTypeName(type)) (\(Fmt.hex16(type)))", "vlan.etype", .int(Int64(type)), o + 2, 2)
        if id == 0xFFF { ctx.flag(.warning, .malformed, "Reserved VLAN ID 4095", on: node) }
        ctx.encapsulationDepth += 1
        guard ctx.encapsulationDepth < 8 else { ctx.malformed("VLAN", node, "too many nested tags"); return }
        Dissector.etherType(ctx, type, o + 4)
    }

    static func mpls(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        var off = o
        let node = ctx.layer("mpls", "MultiProtocol Label Switching", o, 4)
        var labels: [UInt32] = []
        while let entry = d.be32(off) {
            let label = entry >> 12, tc = (entry >> 9) & 7, bos = (entry >> 8) & 1, ttl = entry & 0xFF
            labels.append(label)
            ctx.add(node, "Label: \(label), TC: \(tc), S: \(bos), TTL: \(ttl)", "mpls.label", .int(Int64(label)), off, 4)
            off += 4
            if bos == 1 || labels.count > 16 { break }
        }
        ctx.setInfo("MPLS labels \(labels.map(String.init).joined(separator: "/"))")
        guard let first = d.u8(off) else { return }
        switch first >> 4 {
        case 4: IP.v4(ctx, off)
        case 6: IP.v6(ctx, off)
        default: if first == 0 { Dissector.ethernet(ctx, off + 4) }  // PW control word + Ethernet
        }
    }

    static func pppoe(_ ctx: DissectionContext, _ o: Int, session: Bool) {
        let d = ctx.data
        guard let code = d.u8(o + 1), let sid = d.be16(o + 2), let len = d.be16(o + 4) else {
            ctx.malformed("PPPoE", ctx.layer("pppoe", "PPPoE", o, d.count - o)); return
        }
        let codes: [UInt8: String] = [0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xA7: "PADT", 0x00: "Session Data"]
        let node = ctx.layer(session ? "pppoes" : "pppoed", "PPP-over-Ethernet \(codes[code] ?? "code \(code)")", o, 6,
                             display: session ? "PPPoES" : "PPPoED")
        ctx.add(node, "Code: \(codes[code] ?? "?") (\(Fmt.hex8(code)))", "pppoe.code", .int(Int64(code)), o + 1, 1)
        ctx.add(node, "Session ID: \(Fmt.hex16(sid))", "pppoe.session_id", .int(Int64(sid)), o + 2, 2)
        ctx.add(node, "Payload Length: \(len)", "pppoe.payload_length", .int(Int64(len)), o + 4, 2)
        ctx.setInfo(codes[code] ?? "PPPoE")
        if code == 0xA7 { ctx.flag(.warning, .response, "PPPoE session terminated (PADT)", key: "pppoe.padt", on: node) }
        if session { Dissector.ppp(ctx, o + 6) }
    }

    static func lldp(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        let node = ctx.layer("lldp", "Link Layer Discovery Protocol", o, d.count - o, display: "LLDP")
        var off = o
        var chassis = "", port = "", sysName = ""
        let names = [0: "End", 1: "Chassis ID", 2: "Port ID", 3: "TTL", 4: "Port Description", 5: "System Name",
                     6: "System Description", 7: "Capabilities", 8: "Management Address", 127: "Organization Specific"]
        while let hdr = d.be16(off) {
            let type = Int(hdr >> 9), len = Int(hdr & 0x1FF)
            guard off + 2 + len <= d.count else { ctx.malformed("LLDP", node, "TLV exceeds frame"); break }
            let value = d.sub(off + 2, len) ?? []
            var text = ""
            switch type {
            case 1, 2:
                let sub = value.first ?? 0
                let body = Array(value.dropFirst())
                text = (sub == 4 && body.count == 6) || (type == 2 && sub == 3 && body.count == 6)
                    ? Fmt.mac(body) : String(decoding: body, as: UTF8.self)
                if type == 1 { chassis = text } else { port = text }
            case 3: text = "\(d.be16(off + 2) ?? 0) s"
            case 4, 5, 6: text = String(decoding: value, as: UTF8.self)
                if type == 5 { sysName = text; ctx.index("lldp.tlv.system.name", .string(text)) }
            default: text = "\(len) bytes"
            }
            ctx.add(node, "\(names[type] ?? "TLV \(type)"): \(text)", nil, nil, off, 2 + len)
            off += 2 + len
            if type == 0 { break }
        }
        ctx.setInfo("Chassis \(chassis) Port \(port)\(sysName.isEmpty ? "" : " System \(sysName)")")
    }

    static func cdp(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        let node = ctx.layer("cdp", "Cisco Discovery Protocol", o, d.count - o, display: "CDP")
        var off = o + 4
        var device = "", port = ""
        while let type = d.be16(off), let len = d.be16(off + 2), len >= 4, off + Int(len) <= d.count {
            let value = d.sub(off + 4, Int(len) - 4) ?? []
            let str = String(decoding: value, as: UTF8.self)
            switch type {
            case 0x0001: device = str; ctx.add(node, "Device ID: \(str)", "cdp.deviceid", .string(str), off, Int(len))
            case 0x0003: port = str; ctx.add(node, "Port ID: \(str)", "cdp.portid", .string(str), off, Int(len))
            case 0x0005: ctx.add(node, "Software: \(str.prefix(80))", nil, nil, off, Int(len))
            case 0x0006: ctx.add(node, "Platform: \(str)", "cdp.platform", .string(str), off, Int(len))
            case 0x000A: ctx.add(node, "Native VLAN: \(d.be16(off + 4) ?? 0)", "cdp.native_vlan", .int(Int64(d.be16(off + 4) ?? 0)), off, Int(len))
            default: ctx.add(node, "TLV \(Fmt.hex16(type)) (\(len) bytes)", nil, nil, off, Int(len))
            }
            off += Int(len)
        }
        ctx.setInfo("Device ID: \(device)  Port ID: \(port)")
    }

    static func stp(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let proto = d.be16(o), let ver = d.u8(o + 2), let type = d.u8(o + 3) else {
            ctx.malformed("STP", ctx.layer("stp", "Spanning Tree Protocol", o, d.count - o)); return
        }
        let vname = ver == 0 ? "STP" : ver == 2 ? "RSTP" : ver == 3 ? "MSTP" : "STP v\(ver)"
        let node = ctx.layer("stp", "Spanning Tree Protocol", o, d.count - o, display: vname)
        ctx.add(node, "Protocol Identifier: \(Fmt.hex16(proto))", nil, nil, o, 2)
        ctx.add(node, "Version: \(vname) (\(ver))", "stp.version", .int(Int64(ver)), o + 2, 1)
        ctx.add(node, "BPDU Type: \(type == 0x80 ? "TCN" : type == 2 ? "RST/MST" : "Configuration") (\(Fmt.hex8(type)))",
                "stp.type", .int(Int64(type)), o + 3, 1)
        if type == 0x80 {
            ctx.setInfo("Topology Change Notification")
            ctx.flag(.warning, .protocolError, "STP topology change notification", key: "stp.tcn", on: node)
            return
        }
        guard let flags = d.u8(o + 4), let rootPrio = d.be16(o + 5), let rootMAC = d.sub(o + 7, 6),
              let cost = d.be32(o + 13), let port = d.be16(o + 25) else { ctx.malformed("STP", node); return }
        ctx.add(node, "Flags: \(Fmt.hex8(flags))\(flags & 0x01 != 0 ? " (Topology Change)" : "")", "stp.flags", .int(Int64(flags)), o + 4, 1)
        ctx.add(node, "Root Identifier: \(rootPrio) / \(Fmt.mac(rootMAC))", "stp.root.hw", .mac(rootMAC), o + 5, 8)
        ctx.add(node, "Root Path Cost: \(cost)", "stp.root.cost", .int(Int64(cost)), o + 13, 4)
        ctx.add(node, "Port identifier: \(Fmt.hex16(port))", "stp.port", .int(Int64(port)), o + 25, 2)
        ctx.setInfo("Conf. Root = \(rootPrio)/\(Fmt.mac(rootMAC))  Cost = \(cost)  Port = \(Fmt.hex16(port))")
        if flags & 0x01 != 0 {
            ctx.flag(.warning, .protocolError, "STP topology change flag set", key: "stp.tc", on: node)
        }
    }

    static func eapol(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let ver = d.u8(o), let type = d.u8(o + 1) else {
            ctx.malformed("EAPOL", ctx.layer("eapol", "802.1X Authentication", o, d.count - o)); return
        }
        let types = [0: "EAP Packet", 1: "Start", 2: "Logoff", 3: "Key", 4: "Encapsulated ASF Alert"]
        let node = ctx.layer("eapol", "802.1X Authentication", o, d.count - o, display: "EAPOL")
        ctx.add(node, "Version: \(ver)", "eapol.version", .int(Int64(ver)), o, 1)
        ctx.add(node, "Type: \(types[Int(type)] ?? "?") (\(type))", "eapol.type", .int(Int64(type)), o + 1, 1)
        if type == 0, let code = d.u8(o + 4) {
            let codes = [1: "Request", 2: "Response", 3: "Success", 4: "Failure"]
            ctx.add(node, "EAP Code: \(codes[Int(code)] ?? "?") (\(code))", "eap.code", .int(Int64(code)), o + 4, 1)
            ctx.setInfo("EAP \(codes[Int(code)] ?? "code \(code)")")
            if code == 4 { ctx.flag(.error, .response, "EAP authentication failure", key: "eap.failure", on: node) }
        } else if type == 3 {
            ctx.setInfo("Key (Message of 4-way handshake)")
        } else {
            ctx.setInfo(types[Int(type)] ?? "EAPOL type \(type)")
        }
    }

    static func slow(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let sub = d.u8(o) else { ctx.malformed("Slow", nil); return }
        if sub == 1, let actorState = d.u8(o + 22) {
            let node = ctx.layer("lacp", "Link Aggregation Control Protocol", o, d.count - o, display: "LACP")
            let sys = d.sub(o + 6, 6) ?? []
            ctx.add(node, "Actor System: \(Fmt.mac(sys))", "lacp.actor.sysid", .mac(sys), o + 6, 6)
            ctx.add(node, "Actor Key: \(d.be16(o + 12) ?? 0)", "lacp.actor.key", .int(Int64(d.be16(o + 12) ?? 0)), o + 12, 2)
            ctx.add(node, "Actor State: \(Fmt.hex8(actorState))", "lacp.actor.state", .int(Int64(actorState)), o + 22, 1)
            ctx.setInfo("Actor \(Fmt.mac(sys)) state \(Fmt.hex8(actorState))")
            // Bit 3 = Synchronization. Out-of-sync member means the bundle is not forwarding on that port.
            if actorState & 0x08 == 0 {
                ctx.flag(.warning, .protocolError, "LACP actor not in sync", key: "lacp.out_of_sync", on: node)
            }
        } else {
            simple(ctx, "slow", "Slow", sub == 3 ? "OAM (802.3ah)" : "Slow Protocols subtype \(sub)", o)
        }
    }
}
