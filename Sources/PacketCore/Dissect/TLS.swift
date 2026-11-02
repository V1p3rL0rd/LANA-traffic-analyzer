import Foundation

enum TLS {
    static let versions: [UInt16: String] = [0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"]
    static let handshakeTypes: [UInt8: String] = [
        0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions",
        11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done",
        15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished",
    ]
    static let alerts: [UInt8: String] = [
        0: "Close Notify", 10: "Unexpected Message", 20: "Bad Record MAC", 22: "Record Overflow", 40: "Handshake Failure",
        42: "Bad Certificate", 43: "Unsupported Certificate", 44: "Certificate Revoked", 45: "Certificate Expired",
        46: "Certificate Unknown", 47: "Illegal Parameter", 48: "Unknown CA", 49: "Access Denied", 50: "Decode Error",
        51: "Decrypt Error", 70: "Protocol Version", 71: "Insufficient Security", 80: "Internal Error",
        86: "Inappropriate Fallback", 90: "User Canceled", 109: "Missing Extension", 110: "Unsupported Extension",
        112: "Unrecognized Name", 116: "Certificate Required", 120: "No Application Protocol",
    ]
    /// NULL / EXPORT / RC4 / DES / 3DES / anonymous suites.
    static let weakCiphers: Set<UInt16> = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x000A,
                                           0x0016, 0x0018, 0x001B, 0x0034, 0x003B, 0xC007, 0xC011, 0xC012, 0xC008]

    static func looksLikeRecord(_ d: [UInt8], _ o: Int) -> Bool {
        guard let t = d.u8(o), (20 ... 24).contains(t), let v = d.be16(o + 1), (0x0300 ... 0x0304).contains(v),
              let len = d.be16(o + 3) else { return false }
        return len > 0 && len <= 18432
    }

    static func tcp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        dissect(ctx, o, end, name: "TLS")
    }

    static func dissect(_ ctx: DissectionContext, _ o: Int, _ end: Int, name: String) -> Bool {
        let d = ctx.data
        guard looksLikeRecord(d, o) else {
            ctx.layer("tls", "Transport Layer Security (continuation)", o, end - o, display: name)
            ctx.info += "  Continuation Data"
            return true
        }
        let node = ctx.layer("tls", "Transport Layer Security", o, end - o, display: name)
        var p = o
        var infos: [String] = []
        var count = 0
        while p + 5 <= end, looksLikeRecord(d, p), count < 32 {
            count += 1
            let type = d[p], ver = d.be16(p + 1)!, len = Int(d.be16(p + 3)!)
            let typeName = [20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"][Int(type)] ?? "?"
            let rec = ctx.add(node, "\(versions[ver] ?? "?") Record Layer: \(typeName) Protocol, Length: \(len)",
                              "tls.record.content_type", .int(Int64(type)), p, 5 + len)
            ctx.index("tls.record.version", .int(Int64(ver)))
            let body = p + 5
            let bodyEnd = min(end, body + len)
            switch type {
            case 22:
                if let hs = handshake(ctx, rec, body, bodyEnd) { infos.append(hs) } else { infos.append("Encrypted Handshake Message") }
            case 21:
                if bodyEnd - body == 2 {
                    let level = d[body], desc = d[body + 1]
                    let dname = alerts[desc] ?? "Alert \(desc)"
                    ctx.add(rec, "Alert: Level \(level == 2 ? "Fatal" : "Warning"), Description: \(dname)", "tls.alert_message.desc",
                            .int(Int64(desc)), body, 2)
                    infos.append("Alert (Level: \(level == 2 ? "Fatal" : "Warning"), Description: \(dname))")
                    if level == 2 {
                        ctx.flag(.error, .response, "TLS fatal alert: \(dname)", key: "tls.alert.fatal", on: rec)
                    } else if desc != 0 {
                        ctx.flag(.warning, .response, "TLS warning alert: \(dname)", key: "tls.alert.warning", on: rec)
                    }
                } else {
                    infos.append("Encrypted Alert")
                    ctx.flag(.note, .response, "Encrypted alert (often close_notify)", key: "tls.alert.encrypted", on: rec)
                }
            case 20: infos.append("Change Cipher Spec")
            case 23: infos.append("Application Data")
            case 24:
                infos.append("Heartbeat")
                ctx.flag(.warning, .security, "TLS Heartbeat (check for CVE-2014-0160)", key: "tls.heartbeat", on: rec)
            default: break
            }
            p += 5 + len
        }
        // Collapse "Application Data, Application Data, ..." like Wireshark.
        var collapsed: [String] = []
        for i in infos where collapsed.last != i { collapsed.append(i) }
        ctx.info = collapsed.joined(separator: ", ")
        return true
    }

    private static func handshake(_ ctx: DissectionContext, _ rec: Field, _ o: Int, _ end: Int) -> String? {
        let d = ctx.data
        guard let type = d.u8(o), let len = d.be24(o + 1), let name = handshakeTypes[type], Int(len) <= 1 << 20 else { return nil }
        let hs = ctx.add(rec, "Handshake Protocol: \(name)", "tls.handshake.type", .int(Int64(type)), o, 4 + Int(len))
        var info = name
        guard type == 1 || type == 2 else { return info }

        guard let legacyVer = d.be16(o + 4) else { return info }
        var p = o + 6 + 32          // version + random
        guard let sidLen = d.u8(p) else { return info }
        p += 1 + Int(sidLen)
        var selectedCipher: UInt16?
        if type == 1 {
            guard let csLen = d.be16(p) else { return info }
            ctx.add(hs, "Cipher Suites (\(csLen / 2) suites)", "tls.handshake.cipher_suites_length", .int(Int64(csLen)), p, 2 + Int(csLen))
            p += 2 + Int(csLen)
            guard let compLen = d.u8(p) else { return info }
            p += 1 + Int(compLen)
        } else {
            selectedCipher = d.be16(p)
            if let c = selectedCipher {
                ctx.add(hs, "Cipher Suite: \(Fmt.hex16(c))", "tls.handshake.ciphersuite", .int(Int64(c)), p, 2)
            }
            p += 3
        }
        var negotiated = legacyVer
        if let extLen = d.be16(p) {
            var e = p + 2
            let extEnd = min(end, e + Int(extLen))
            while e + 4 <= extEnd, let et = d.be16(e), let el = d.be16(e + 2) {
                let v = e + 4
                switch et {
                case 0:  // server_name
                    if let nl = d.be16(v + 3), let nb = d.sub(v + 5, Int(nl)) {
                        let sni = String(decoding: nb, as: UTF8.self)
                        ctx.add(hs, "Server Name: \(sni)", "tls.handshake.extensions_server_name", .string(sni), e, 4 + Int(el))
                        info += " (SNI=\(sni))"
                    }
                case 16: // ALPN
                    var a = v + 2, protos: [String] = []
                    while a < v + Int(el), let l = d.u8(a), let s = d.sub(a + 1, Int(l)) {
                        protos.append(String(decoding: s, as: UTF8.self)); a += 1 + Int(l)
                    }
                    ctx.add(hs, "ALPN: \(protos.joined(separator: ", "))", "tls.handshake.extensions_alpn_str",
                            .string(protos.joined(separator: ",")), e, 4 + Int(el))
                case 43: // supported_versions
                    if type == 2, let sv = d.be16(v) { negotiated = sv }
                    if type == 1, let n = d.u8(v) {
                        let vs = stride(from: v + 1, to: v + 1 + Int(n), by: 2).compactMap { d.be16($0) }.compactMap { versions[$0] }
                        ctx.add(hs, "Supported Versions: \(vs.joined(separator: ", "))", nil, nil, e, 4 + Int(el))
                    }
                default: break
                }
                e += 4 + Int(el)
            }
        }
        if type == 2 {
            let vname = versions[negotiated] ?? Fmt.hex16(negotiated)
            ctx.add(hs, "Negotiated Version: \(vname)", "tls.handshake.version", .int(Int64(negotiated)), o + 4, 2)
            info += " (\(vname))"
            if negotiated < 0x0303 {
                ctx.flag(.warning, .security, "Deprecated protocol negotiated: \(vname)", key: "tls.deprecated_version", on: hs)
            }
            if let c = selectedCipher, weakCiphers.contains(c) {
                ctx.flag(.warning, .security, "Weak cipher suite selected (\(Fmt.hex16(c)))", key: "tls.weak_cipher", on: hs)
            }
        }
        return info
    }

    // MARK: QUIC

    static func looksLikeQUIC(_ d: [UInt8], _ o: Int) -> Bool {
        guard let b = d.u8(o), b & 0xC0 == 0xC0, let v = d.be32(o + 1) else { return false }
        return v == 1 || v == 0x6B33_43CF || v == 0 || (v & 0xFF00_0000) == 0xFF00_0000
    }

    static func quic(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let first = d.u8(o) else { return false }
        if first & 0x80 == 0 {
            guard first & 0x40 != 0 else { return false }
            ctx.layer("quic", "QUIC IETF (short header)", o, end - o, display: "QUIC")
            ctx.setInfo("Protected Payload (KP\(first & 0x04 != 0 ? 1 : 0))")
            return true
        }
        guard let version = d.be32(o + 1), let dcil = d.u8(o + 5) else { return false }
        let node = ctx.layer("quic", "QUIC IETF", o, end - o, display: "QUIC")
        if version == 0 {
            ctx.setInfo("Version Negotiation")
            ctx.flag(.warning, .protocolError, "QUIC version negotiation", key: "quic.version_negotiation", on: node)
            return true
        }
        let types = ["Initial", "0-RTT", "Handshake", "Retry"]
        let ptype = Int((first >> 4) & 0x3)
        let vname = version == 1 ? "1" : version == 0x6B33_43CF ? "2" : Fmt.hex32(version)
        ctx.add(node, "Version: \(vname)", "quic.version", .int(Int64(version)), o + 1, 4)
        ctx.add(node, "Packet Type: \(types[ptype])", "quic.long.packet_type", .int(Int64(ptype)), o, 1)
        if let dcid = d.sub(o + 6, Int(dcil)) {
            ctx.add(node, "Destination Connection ID: \(Fmt.hex(dcid))", "quic.dcid", .bytes(dcid), o + 6, Int(dcil))
            ctx.setInfo("\(types[ptype]), DCID=\(Fmt.hex(dcid))")
        } else {
            ctx.setInfo(types[ptype])
        }
        return true
    }
}
