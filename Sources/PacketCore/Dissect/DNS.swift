import Foundation

enum DNS {
    static let types: [UInt16: String] = [
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 28: "AAAA", 32: "NB",
        33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
        99: "SPF", 252: "AXFR", 255: "ANY", 257: "CAA",
    ]
    static let rcodes = [0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented",
                         5: "Refused", 6: "YXDomain", 7: "YXRRSet", 8: "NXRRSet", 9: "Not authoritative", 10: "Not zone"]

    static func udp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        message(ctx, o, end, prefixLength: false, netbios: false)
    }

    static func tcp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        guard let len = ctx.data.be16(o), len >= 12 else { return false }
        return message(ctx, o + 2, min(end, o + 2 + Int(len)), prefixLength: true, netbios: false)
    }

    static func nbns(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        message(ctx, o, end, prefixLength: false, netbios: true)
    }

    private static func message(_ ctx: DissectionContext, _ o: Int, _ end: Int, prefixLength: Bool, netbios: Bool) -> Bool {
        let d = ctx.data
        guard end - o >= 12, let id = d.be16(o), let flags = d.be16(o + 2), let qd = d.be16(o + 4),
              let an = d.be16(o + 6), let ns = d.be16(o + 8), let ar = d.be16(o + 10) else { return false }
        // Sanity: reject random payloads on port 53 / 5353.
        guard qd <= 64, an <= 512, ns <= 512, ar <= 512 else { return false }

        let mdns = (ctx.tcp == nil) && (ctx.fields["udp.port"]?.contains(.int(5353)) ?? false)
        let llmnr = ctx.fields["udp.port"]?.contains(.int(5355)) ?? false || ctx.fields["tcp.port"]?.contains(.int(5355)) ?? false
        let (abbrev, display) = netbios ? ("nbns", "NBNS") : mdns ? ("mdns", "MDNS") : llmnr ? ("llmnr", "LLMNR") : ("dns", "DNS")
        let isResponse = flags & 0x8000 != 0
        let opcode = (flags >> 11) & 0xF
        let rcode = Int(flags & 0xF)
        let node = ctx.layer(abbrev, netbios ? "NetBIOS Name Service" : "Domain Name System (\(isResponse ? "response" : "query"))",
                             prefixLength ? o - 2 : o, end - o + (prefixLength ? 2 : 0), display: display)
        ctx.add(node, "Transaction ID: \(Fmt.hex16(id))", "dns.id", .int(Int64(id)), o, 2)
        let fnode = ctx.add(node, "Flags: \(Fmt.hex16(flags)) \(isResponse ? "Standard query response" : "Standard query")\(rcode != 0 ? ", \(rcodes[rcode] ?? "rcode \(rcode)")" : "")",
                            "dns.flags", .int(Int64(flags)), o + 2, 2)
        ctx.index("dns.flags.response", .bool(isResponse))
        ctx.index("dns.flags.rcode", .int(Int64(rcode)))
        ctx.index("dns.flags.opcode", .int(Int64(opcode)))
        ctx.add(node, "Questions: \(qd), Answer RRs: \(an), Authority RRs: \(ns), Additional RRs: \(ar)", "dns.count.answers", .int(Int64(an)), o + 4, 8)

        var p = o + 12
        var qnames: [String] = []
        var qtypes: [String] = []
        for _ in 0 ..< qd {
            guard case let (name, next)? = readName(d, p, base: o, end: end) else { ctx.malformed(display, node, "bad question name"); return true }
            guard let qtype = d.be16(next), let qclass = d.be16(next + 2) else { ctx.malformed(display, node); return true }
            let shown = netbios ? decodeNetBIOS(name) : name
            qnames.append(shown)
            qtypes.append(types[qtype] ?? "TYPE\(qtype)")
            ctx.add(node, "Query: \(shown): type \(types[qtype] ?? String(qtype)), class \(qclass & 0x7FFF == 1 ? "IN" : String(qclass))",
                    "dns.qry.name", .string(shown), p, next + 4 - p)
            ctx.index("dns.qry.type", .int(Int64(qtype)))
            if !netbios { tunnelHeuristic(ctx, shown, node) }
            p = next + 4
        }

        var answers: [String] = []
        let sections = [(Int(an), "Answer"), (Int(ns), "Authority"), (Int(ar), "Additional")]
        outer: for (count, section) in sections where count > 0 {
            let sNode = ctx.add(node, "\(section) records", nil, nil, p, 0)
            for _ in 0 ..< count {
                guard case let (name, next)? = readName(d, p, base: o, end: end),
                      let type = d.be16(next), let cls = d.be16(next + 2), let ttl = d.be32(next + 4),
                      let rdlen = d.be16(next + 8), next + 10 + Int(rdlen) <= end else {
                    ctx.malformed(display, sNode, "truncated resource record"); break outer
                }
                let r = next + 10
                let value = rdata(d, type, r, Int(rdlen), base: o, end: end)
                let tname = types[type] ?? "TYPE\(type)"
                ctx.add(sNode, "\(netbios ? decodeNetBIOS(name) : name): type \(tname), class \(cls & 0x7FFF == 1 ? "IN" : String(cls)), ttl \(ttl): \(value)",
                        "dns.resp.name", .string(name), p, r + Int(rdlen) - p)
                if section == "Answer" {
                    answers.append("\(tname) \(value)")
                    switch type {
                    case 1: if let v = d.be32(r) { ctx.index("dns.a", .ipv4(v)) }
                    case 28: if let v = d.sub(r, 16) { ctx.index("dns.aaaa", .ipv6(v)) }
                    case 5: ctx.index("dns.cname", .string(value))
                    default: break
                    }
                    ctx.index("dns.resp.ttl", .int(Int64(ttl)))
                }
                p = r + Int(rdlen)
            }
        }

        let opText = opcode == 0 ? "Standard query" : opcode == 5 ? "Dynamic update" : opcode == 4 ? "Notify" : "Opcode \(opcode)"
        var info = "\(opText)\(isResponse ? " response" : "") \(Fmt.hex16(id)) "
        info += zip(qtypes, qnames).map { "\($0) \($1)" }.joined(separator: ", ")
        if isResponse {
            if rcode != 0 { info += " \(rcodes[rcode] ?? "rcode \(rcode)")" }
            if !answers.isEmpty { info += " " + answers.prefix(4).joined(separator: " ") }
        }
        ctx.setInfo(info)

        if isResponse {
            switch rcode {
            case 0: break
            case 3:
                ctx.flag(.warning, .response, "DNS: No such name (NXDOMAIN)", key: "dns.nxdomain", on: fnode)
            case 1, 2, 4, 5:
                ctx.flag(.error, .response, "DNS error: \(rcodes[rcode] ?? String(rcode))", key: "dns.error", on: fnode)
            default:
                ctx.flag(.warning, .response, "DNS rcode \(rcode)", key: "dns.error", on: fnode)
            }
            if flags & 0x0200 != 0 {
                ctx.flag(.warning, .protocolError, "Truncated response (TC) — client will retry over TCP", key: "dns.flags.truncated", on: fnode)
            }
        }
        if qtypes.contains("AXFR") {
            ctx.flag(.warning, .security, "Zone transfer (AXFR) request", key: "dns.axfr", on: node)
        }
        if qtypes.contains("ANY"), !mdns {
            ctx.flag(.note, .security, "ANY query (amplification vector)", key: "dns.any", on: node)
        }
        return true
    }

    /// Long, random-looking labels → DNS tunnelling / exfiltration (iodine, dnscat2, DGA malware).
    private static func tunnelHeuristic(_ ctx: DissectionContext, _ name: String, _ node: Field) {
        let labels = name.split(separator: ".")
        guard let longest = labels.map(\.count).max() else { return }
        if longest > 50 || name.count > 120 {
            ctx.flag(.warning, .security, "Unusually long DNS name (possible tunnelling/exfiltration)", key: "dns.suspicious_name", on: node)
        }
    }

    static func readName(_ d: [UInt8], _ start: Int, base: Int, end: Int) -> (String, Int)? {
        var labels: [String] = []
        var p = start
        var next: Int?
        var jumps = 0
        while true {
            guard p < end, let len = d.u8(p) else { return nil }
            if len == 0 { p += 1; break }
            if len & 0xC0 == 0xC0 {
                guard let ptr = d.be16(p) else { return nil }
                if next == nil { next = p + 2 }
                jumps += 1
                guard jumps < 32 else { return nil }    // compression loop
                p = base + Int(ptr & 0x3FFF)
                continue
            }
            guard len < 64, let bytes = d.sub(p + 1, Int(len)), p + 1 + Int(len) <= end else { return nil }
            labels.append(String(decoding: bytes, as: UTF8.self))
            p += 1 + Int(len)
            guard labels.count < 128 else { return nil }
        }
        return (labels.isEmpty ? "<Root>" : labels.joined(separator: "."), next ?? p)
    }

    private static func rdata(_ d: [UInt8], _ type: UInt16, _ r: Int, _ len: Int, base: Int, end: Int) -> String {
        switch type {
        case 1 where len == 4: return d.be32(r).map(Fmt.ipv4) ?? "?"
        case 28 where len == 16: return d.sub(r, 16).map(Fmt.ipv6) ?? "?"
        case 2, 5, 12: return readName(d, r, base: base, end: end)?.0 ?? "?"
        case 15: return "\(d.be16(r) ?? 0) \(readName(d, r + 2, base: base, end: end)?.0 ?? "?")"
        case 33: return "\(d.be16(r) ?? 0) \(d.be16(r + 2) ?? 0) \(d.be16(r + 4) ?? 0) \(readName(d, r + 6, base: base, end: end)?.0 ?? "?")"
        case 16:
            var p = r, out: [String] = []
            while p < r + len, let l = d.u8(p), let s = d.sub(p + 1, Int(l)) {
                out.append(String(decoding: s, as: UTF8.self)); p += 1 + Int(l)
            }
            return out.map { "\"\($0.prefix(80))\"" }.joined(separator: " ")
        case 6: return "mname \(readName(d, r, base: base, end: end)?.0 ?? "?")"
        default: return "\(len) bytes"
        }
    }

    /// NetBIOS first-level encoding: each nibble + 'A'.
    static func decodeNetBIOS(_ s: String) -> String {
        let label = s.split(separator: ".").first.map(String.init) ?? s
        let bytes = Array(label.utf8)
        guard bytes.count == 32, bytes.allSatisfy({ $0 >= 0x41 && $0 <= 0x50 }) else { return s }
        var out: [UInt8] = []
        for i in stride(from: 0, to: 32, by: 2) { out.append((bytes[i] - 0x41) << 4 | (bytes[i + 1] - 0x41)) }
        let suffix = out.last ?? 0
        let name = String(decoding: out.dropLast(), as: UTF8.self).trimmingCharacters(in: .whitespaces)
        return "\(name)<\(String(format: "%02x", suffix))>"
    }
}
