import Foundation

enum Transport {
    struct TCPFlags {
        static let fin: UInt16 = 0x001, syn: UInt16 = 0x002, rst: UInt16 = 0x004, psh: UInt16 = 0x008
        static let ack: UInt16 = 0x010, urg: UInt16 = 0x020, ece: UInt16 = 0x040, cwr: UInt16 = 0x080, ae: UInt16 = 0x100

        static func names(_ f: UInt16) -> String {
            let all: [(UInt16, String)] = [(syn, "SYN"), (fin, "FIN"), (rst, "RST"), (psh, "PSH"), (ack, "ACK"),
                                           (urg, "URG"), (ece, "ECE"), (cwr, "CWR"), (ae, "AE")]
            return all.filter { f & $0.0 != 0 }.map(\.1).joined(separator: ", ")
        }
    }

    // MARK: TCP

    static func tcp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ ip: IPInfo) {
        let d = ctx.data
        guard let sp = d.be16(o), let dp = d.be16(o + 2), let seq = d.be32(o + 4), let ack = d.be32(o + 8),
              let offFlags = d.be16(o + 12), let win = d.be16(o + 14), let csum = d.be16(o + 16), let urp = d.be16(o + 18) else {
            ctx.malformed("TCP", ctx.layer("tcp", "Transmission Control Protocol", o, end - o, display: "TCP")); return
        }
        let hlen = Int(offFlags >> 12) * 4
        let flags = offFlags & 0x01FF
        let payloadLen = max(0, end - o - hlen)
        let node = ctx.layer("tcp", "Transmission Control Protocol, Src Port: \(sp), Dst Port: \(dp), Seq: \(seq), Len: \(payloadLen)",
                             o, max(20, hlen), display: "TCP")
        ctx.add(node, "Source Port: \(sp)", "tcp.srcport", .int(Int64(sp)), o, 2)
        ctx.add(node, "Destination Port: \(dp)", "tcp.dstport", .int(Int64(dp)), o + 2, 2)
        ctx.index("tcp.port", .int(Int64(sp))); ctx.index("tcp.port", .int(Int64(dp)))
        ctx.add(node, "Sequence Number: \(seq)", "tcp.seq", .int(Int64(seq)), o + 4, 4)
        ctx.add(node, "Acknowledgment Number: \(ack)", "tcp.ack", .int(Int64(ack)), o + 8, 4)
        ctx.add(node, "Header Length: \(hlen) bytes", "tcp.hdr_len", .int(Int64(hlen)), o + 12, 1)
        let fNode = ctx.add(node, "Flags: \(String(format: "0x%03x", flags)) (\(TCPFlags.names(flags)))", "tcp.flags", .int(Int64(flags)), o + 12, 2)
        for (bit, key) in [(TCPFlags.syn, "syn"), (TCPFlags.ack, "ack"), (TCPFlags.fin, "fin"), (TCPFlags.rst, "reset"),
                           (TCPFlags.psh, "push"), (TCPFlags.urg, "urg"), (TCPFlags.ece, "ece"), (TCPFlags.cwr, "cwr")] {
            ctx.index("tcp.flags.\(key)", .bool(flags & bit != 0))
        }
        ctx.add(node, "Window: \(win)", "tcp.window_size_value", .int(Int64(win)), o + 14, 2)
        let cs = ctx.add(node, "Checksum: \(Fmt.hex16(csum))", "tcp.checksum", .int(Int64(csum)), o + 16, 2)
        if flags & TCPFlags.urg != 0 { ctx.add(node, "Urgent Pointer: \(urp)", "tcp.urgent_pointer", .int(Int64(urp)), o + 18, 2) }
        ctx.add(node, "TCP payload (\(payloadLen) bytes)", "tcp.len", .int(Int64(payloadLen)), o + hlen, payloadLen)

        guard hlen >= 20 else { ctx.malformed("TCP", node, "header length \(hlen) < 20"); return }
        guard o + hlen <= end else { ctx.malformed("TCP", node, "header length exceeds segment"); return }

        // Options
        var wscale: UInt8?
        var optInfo: [String] = []
        if hlen > 20 {
            let optNode = ctx.add(node, "Options: (\(hlen - 20) bytes)", nil, nil, o + 20, hlen - 20)
            var p = o + 20
            while p < o + hlen, let kind = d.u8(p) {
                if kind == 0 { break }
                if kind == 1 { p += 1; continue }
                guard let len = d.u8(p + 1), len >= 2, p + Int(len) <= o + hlen else {
                    ctx.malformed("TCP", optNode, "bad option length"); break
                }
                switch kind {
                case 2: let mss = d.be16(p + 2) ?? 0
                    ctx.add(optNode, "Maximum segment size: \(mss) bytes", "tcp.options.mss_val", .int(Int64(mss)), p, Int(len))
                    optInfo.append("MSS=\(mss)")
                case 3: wscale = d.u8(p + 2)
                    ctx.add(optNode, "Window scale: \(wscale ?? 0) (multiply by \(1 << Int(min(wscale ?? 0, 14))))",
                            "tcp.options.wscale.shift", .int(Int64(wscale ?? 0)), p, Int(len))
                    optInfo.append("WS=\(1 << Int(min(wscale ?? 0, 14)))")
                    if (wscale ?? 0) > 14 { ctx.flag(.warning, .protocolError, "Window scale shift > 14 (RFC 7323)", on: optNode) }
                case 4: ctx.add(optNode, "SACK permitted", "tcp.options.sack_perm", .bool(true), p, Int(len)); optInfo.append("SACK_PERM")
                case 5: ctx.add(optNode, "SACK: \((Int(len) - 2) / 8) block(s)", "tcp.options.sack", .bool(true), p, Int(len))
                case 8:
                    let tsv = d.be32(p + 2) ?? 0, tse = d.be32(p + 6) ?? 0
                    ctx.add(optNode, "Timestamps: TSval \(tsv), TSecr \(tse)", "tcp.options.timestamp.tsval", .int(Int64(tsv)), p, Int(len))
                    optInfo.append("TSval=\(tsv) TSecr=\(tse)")
                case 30: ctx.add(optNode, "Multipath TCP", "tcp.options.mptcp", .bool(true), p, Int(len))
                case 34: ctx.add(optNode, "TCP Fast Open cookie", "tcp.options.tfo", .bool(true), p, Int(len))
                default: ctx.add(optNode, "Option kind \(kind) (\(len) bytes)", nil, nil, p, Int(len))
                }
                p += Int(len)
            }
        }

        // Stateless anomaly checks
        let synFin = TCPFlags.syn | TCPFlags.fin
        if flags & synFin == synFin {
            ctx.flag(.error, .security, "SYN+FIN set (illegal; scan/evasion)", key: "tcp.flags.synfin", on: fNode)
        }
        if flags & (TCPFlags.syn | TCPFlags.rst) == (TCPFlags.syn | TCPFlags.rst) {
            ctx.flag(.error, .malformed, "SYN+RST set (illegal)", on: fNode)
        }
        if flags & 0x3F == 0 {
            ctx.flag(.error, .security, "No flags set (NULL scan)", key: "tcp.flags.null", on: fNode)
        }
        if flags & (TCPFlags.fin | TCPFlags.psh | TCPFlags.urg) == (TCPFlags.fin | TCPFlags.psh | TCPFlags.urg) {
            ctx.flag(.error, .security, "FIN+PSH+URG set (Xmas scan)", key: "tcp.flags.xmas", on: fNode)
        }
        if flags & TCPFlags.fin != 0, flags & TCPFlags.ack == 0, flags & TCPFlags.syn == 0 {
            ctx.flag(.warning, .security, "FIN without ACK (FIN scan)", key: "tcp.flags.fin_noack", on: fNode)
        }
        if flags & TCPFlags.rst != 0 {
            ctx.flag(.error, .sequence, "Connection reset (RST)", key: "tcp.connection.rst", on: fNode)
        }
        if flags & TCPFlags.syn != 0, payloadLen > 0, !optInfo.contains(where: { $0.hasPrefix("TFO") }) {
            ctx.flag(.note, .protocolError, "SYN with payload", on: node)
        }
        if sp == 0 || dp == 0 { ctx.flag(.error, .malformed, "TCP port 0", key: "tcp.port.zero", on: node) }
        if ctx.validateChecksums, d.count >= end {
            let segLen = end - o
            if Checksum.fold(Checksum.sum(d, o ..< end, initial: ip.pseudoHeaderSum(proto: 6, length: segLen))) != 0 {
                cs.label += " [incorrect]"
                ctx.flag(.error, .checksum, "Bad TCP checksum (may be checksum offload on outgoing packets)", key: "tcp.checksum.bad", on: cs)
            } else { cs.label += " [correct]" }
        }

        ctx.tcp = TCPSegmentFacts(srcAddr: ip.src, dstAddr: ip.dst, srcPort: sp, dstPort: dp, seq: seq, ack: ack,
                                  flags: flags, window: win, windowScale: flags & TCPFlags.syn != 0 ? (wscale ?? 0) : nil,
                                  payloadLength: payloadLen)
        var info = "\(sp) → \(dp) [\(TCPFlags.names(flags))] Seq=\(seq)"
        if flags & TCPFlags.ack != 0 { info += " Ack=\(ack)" }
        info += " Win=\(win) Len=\(payloadLen)"
        if !optInfo.isEmpty { info += " " + optInfo.joined(separator: " ") }
        ctx.setInfo(info)

        if payloadLen > 0 { Apps.dispatch(ctx, tcp: true, sp, dp, o + hlen, end) }
    }

    // MARK: UDP

    static func udp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ ip: IPInfo) {
        let d = ctx.data
        guard let sp = d.be16(o), let dp = d.be16(o + 2), let len = d.be16(o + 4), let csum = d.be16(o + 6) else {
            ctx.malformed("UDP", ctx.layer("udp", "User Datagram Protocol", o, end - o, display: "UDP")); return
        }
        let node = ctx.layer("udp", "User Datagram Protocol, Src Port: \(sp), Dst Port: \(dp)", o, 8, display: "UDP")
        ctx.add(node, "Source Port: \(sp)", "udp.srcport", .int(Int64(sp)), o, 2)
        ctx.add(node, "Destination Port: \(dp)", "udp.dstport", .int(Int64(dp)), o + 2, 2)
        ctx.index("udp.port", .int(Int64(sp))); ctx.index("udp.port", .int(Int64(dp)))
        let lnode = ctx.add(node, "Length: \(len)", "udp.length", .int(Int64(len)), o + 4, 2)
        let cs = ctx.add(node, "Checksum: \(Fmt.hex16(csum))", "udp.checksum", .int(Int64(csum)), o + 6, 2)
        ctx.setInfo("\(sp) → \(dp) Len=\(max(0, Int(len) - 8))")

        guard len >= 8 else { ctx.malformed("UDP", lnode, "length \(len) < 8"); return }
        let available = end - o
        if Int(len) > available, ctx.data.count >= end {
            // Only malformed when IP says the datagram is shorter than UDP claims.
            ctx.flag(.error, .malformed, "UDP length \(len) exceeds IP payload \(available)", key: "udp.length.bad", on: lnode)
        }
        if sp == 0 && dp == 0 { ctx.flag(.error, .malformed, "UDP ports are zero", on: node) }
        if csum == 0, ip.version == 6 {
            ctx.flag(.error, .checksum, "Zero UDP checksum is illegal over IPv6", key: "udp.checksum.zero", on: cs)
        } else if ctx.validateChecksums, csum != 0, d.count >= o + Int(len) {
            let s = Checksum.sum(d, o ..< o + Int(len), initial: ip.pseudoHeaderSum(proto: 17, length: Int(len)))
            if Checksum.fold(s) != 0 {
                cs.label += " [incorrect]"
                ctx.flag(.error, .checksum, "Bad UDP checksum (may be checksum offload)", key: "udp.checksum.bad", on: cs)
            } else { cs.label += " [correct]" }
        }
        let pend = min(end, o + Int(len))
        if pend > o + 8 { Apps.dispatch(ctx, tcp: false, sp, dp, o + 8, pend) }
    }

    // MARK: SCTP

    static func sctp(_ ctx: DissectionContext, _ o: Int, _ end: Int) {
        let d = ctx.data
        guard let sp = d.be16(o), let dp = d.be16(o + 2), let vtag = d.be32(o + 4) else {
            ctx.malformed("SCTP", ctx.layer("sctp", "Stream Control Transmission Protocol", o, end - o, display: "SCTP")); return
        }
        let node = ctx.layer("sctp", "Stream Control Transmission Protocol, Src Port: \(sp), Dst Port: \(dp)", o, end - o, display: "SCTP")
        ctx.add(node, "Source port: \(sp)", "sctp.srcport", .int(Int64(sp)), o, 2)
        ctx.add(node, "Destination port: \(dp)", "sctp.dstport", .int(Int64(dp)), o + 2, 2)
        ctx.index("sctp.port", .int(Int64(sp))); ctx.index("sctp.port", .int(Int64(dp)))
        ctx.add(node, "Verification tag: \(Fmt.hex32(vtag))", "sctp.verification_tag", .int(Int64(vtag)), o + 4, 4)
        let names = [0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK", 6: "ABORT",
                     7: "SHUTDOWN", 8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE"]
        var p = o + 12, chunks: [String] = []
        while p + 4 <= end, let type = d.u8(p), let clen = d.be16(p + 2), clen >= 4, chunks.count < 32 {
            let n = names[Int(type)] ?? "chunk \(type)"
            chunks.append(n)
            let c = ctx.add(node, "\(n) chunk (\(clen) bytes)", "sctp.chunk_type", .int(Int64(type)), p, Int(clen))
            if type == 6 { ctx.flag(.error, .response, "SCTP ABORT", key: "sctp.abort", on: c) }
            if type == 9 { ctx.flag(.error, .protocolError, "SCTP ERROR chunk", key: "sctp.error", on: c) }
            p += (Int(clen) + 3) & ~3
        }
        ctx.setInfo(chunks.joined(separator: " "))
    }
}
