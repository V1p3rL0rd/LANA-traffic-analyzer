import Foundation

/// Stateful cross-packet analysis (Wireshark "tcp.analysis.*" equivalents plus a few IDS-style
/// heuristics). Not thread-safe: drive it from one serial queue in capture order.
public final class AnomalyEngine {
    public struct Config: Sendable {
        public var scanThreshold = 100            // distinct dst:port SYNs per source...
        public var sweepThreshold = 50            // distinct ICMP echo targets per source...
        public var window: Double = 5             // ...within this many seconds
        public var flowIdleTimeout: Double = 300
        public init() {}
    }

    private final class Direction {
        var nextSeq: UInt32?
        var lastAck: UInt32?
        var lastWin: UInt16 = 0
        var wsOption: Int?                        // shift from SYN, nil = no option / not seen
        var sawSYN = false
        var synSeq: UInt32?
        var dupAcks = 0
        var recentSeqs: [UInt32] = []
        var lastTime: Double = 0
    }

    private final class Flow {
        let a = Direction(), b = Direction()
        var lastTime: Double = 0
        var scaleKnown: Bool { a.sawSYN && b.sawSYN }
    }

    private var flows: [String: Flow] = [:]
    private var arpTable: [UInt32: [UInt8]] = [:]
    private var synTargets: [String: [(Double, String)]] = [:]
    private var pingTargets: [String: [(Double, String)]] = [:]
    private var processed = 0
    public let config: Config

    public init(config: Config = Config()) { self.config = config }

    public func reset() {
        flows.removeAll(); arpTable.removeAll(); synTargets.removeAll(); pingTargets.removeAll(); processed = 0
    }

    @discardableResult
    public func analyze(_ ctx: DissectionContext, timestamp: Double) -> [ExpertInfo] {
        var out: [ExpertInfo] = []
        if let t = ctx.tcp { out += tcp(t, timestamp) }
        if let a = ctx.arp { out += arp(a) }
        out += scans(ctx, timestamp)
        processed += 1
        if processed % 20_000 == 0 { purge(now: timestamp) }
        ctx.merge(out)
        return out
    }

    // MARK: TCP

    /// Serial-number arithmetic (RFC 1982) so wrap-around at 2^32 is handled.
    @inline(__always) private func lt(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) < 0 }
    @inline(__always) private func gt(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) > 0 }

    private func tcp(_ t: TCPSegmentFacts, _ now: Double) -> [ExpertInfo] {
        typealias F = Transport.TCPFlags
        let fwdKey = "\(t.srcAddr)|\(t.srcPort)|\(t.dstAddr)|\(t.dstPort)"
        let revKey = "\(t.dstAddr)|\(t.dstPort)|\(t.srcAddr)|\(t.srcPort)"
        let flow: Flow, dir: Direction, rev: Direction
        if let f = flows[fwdKey] { flow = f; dir = f.a; rev = f.b }
        else if let f = flows[revKey] { flow = f; dir = f.b; rev = f.a }
        else { flow = Flow(); flows[fwdKey] = flow; dir = flow.a; rev = flow.b }
        flow.lastTime = now

        var out: [ExpertInfo] = []
        let syn = t.flags & F.syn != 0, fin = t.flags & F.fin != 0, rst = t.flags & F.rst != 0, ack = t.flags & F.ack != 0
        let segLen = UInt32(t.payloadLength) + (syn ? 1 : 0) + (fin ? 1 : 0)

        if syn {
            if dir.sawSYN, dir.synSeq == t.seq {
                out.append(ExpertInfo(.warning, .sequence, "SYN retransmission (no answer from \(t.dstAddr):\(t.dstPort)?)",
                                      key: "tcp.analysis.retransmission"))
            }
            if !dir.sawSYN || dir.synSeq != t.seq { dir.recentSeqs.removeAll(); dir.nextSeq = nil }
            dir.sawSYN = true
            dir.synSeq = t.seq
            dir.wsOption = t.windowScale.map { Int($0) }
        }

        // Effective receive window of the peer (for "window full").
        func scaled(_ d: Direction, _ w: UInt16) -> Int? {
            guard flow.scaleKnown else { return nil }
            let shift = (flow.a.wsOption != nil && flow.b.wsOption != nil) ? min(d.wsOption ?? 0, 14) : 0
            return Int(w) << shift
        }

        if t.window == 0, !syn, !fin, !rst {
            out.append(ExpertInfo(.error, .sequence, "TCP Zero Window — receiver \(t.srcAddr) buffer full", key: "tcp.analysis.zero_window"))
        }

        var isKeepAlive = false
        if let next = dir.nextSeq, !syn, !fin, !rst, t.payloadLength <= 1, t.seq == next &- 1 {
            isKeepAlive = true
            out.append(ExpertInfo(.note, .sequence, "TCP Keep-Alive", key: "tcp.analysis.keep_alive"))
        }

        if !isKeepAlive, let next = dir.nextSeq, segLen > 0, !syn {
            if rev.lastWin == 0, rev.lastAck != nil, t.seq == next, t.payloadLength == 1 {
                out.append(ExpertInfo(.warning, .sequence, "TCP Zero Window Probe", key: "tcp.analysis.zero_window_probe"))
            } else if lt(t.seq, next) {
                if dir.recentSeqs.contains(t.seq) || now - dir.lastTime > 0.003 {
                    if rev.dupAcks >= 2, rev.lastAck == t.seq {
                        out.append(ExpertInfo(.warning, .sequence, "TCP Fast Retransmission", key: "tcp.analysis.fast_retransmission"))
                    } else if let ra = rev.lastAck, !gt(t.seq &+ segLen, ra) {
                        out.append(ExpertInfo(.warning, .sequence, "TCP Spurious Retransmission (already ACKed)", key: "tcp.analysis.spurious_retransmission"))
                    } else {
                        out.append(ExpertInfo(.warning, .sequence, "TCP Retransmission", key: "tcp.analysis.retransmission"))
                    }
                } else {
                    out.append(ExpertInfo(.warning, .sequence, "TCP Out-Of-Order", key: "tcp.analysis.out_of_order"))
                }
            } else if gt(t.seq, next) {
                out.append(ExpertInfo(.warning, .sequence, "Previous segment not captured (\(t.seq &- next) bytes missing)",
                                      key: "tcp.analysis.lost_segment"))
            }
        }

        // Window full: this segment fills the peer's advertised window exactly.
        if t.payloadLength > 0, let peerAck = rev.lastAck, let win = scaled(rev, rev.lastWin), win > 0,
           t.seq &+ UInt32(t.payloadLength) == peerAck &+ UInt32(truncatingIfNeeded: win) {
            out.append(ExpertInfo(.warning, .performance, "TCP Window Full", key: "tcp.analysis.window_full"))
        }

        // Duplicate ACK / window update
        if ack, t.payloadLength == 0, !syn, !fin, !rst, let last = dir.lastAck, last == t.ack {
            if t.window == dir.lastWin, rev.nextSeq != nil {
                dir.dupAcks += 1
                out.append(ExpertInfo(.warning, .sequence, "Dup ACK #\(dir.dupAcks) (ack \(t.ack))", key: "tcp.analysis.duplicate_ack"))
            } else if t.window != dir.lastWin {
                out.append(ExpertInfo(.note, .sequence, "TCP Window Update", key: "tcp.analysis.window_update"))
            }
        } else if ack, dir.lastAck != t.ack {
            dir.dupAcks = 0
        }

        if ack, let peerNext = rev.nextSeq, gt(t.ack, peerNext), !syn {
            out.append(ExpertInfo(.note, .sequence, "ACKed segment that wasn't captured", key: "tcp.analysis.ack_lost_segment"))
        }

        // Update state
        if segLen > 0 {
            let end = t.seq &+ segLen
            if let next = dir.nextSeq { if gt(end, next) { dir.nextSeq = end } } else { dir.nextSeq = end }
            if !dir.recentSeqs.contains(t.seq) {
                dir.recentSeqs.append(t.seq)
                if dir.recentSeqs.count > 64 { dir.recentSeqs.removeFirst(dir.recentSeqs.count - 64) }
            }
        }
        if ack { dir.lastAck = t.ack }
        dir.lastWin = t.window
        dir.lastTime = now
        // Flow state is kept after FIN/RST until idle purge, so late retransmissions are still classified.
        return out
    }

    // MARK: ARP

    private func arp(_ a: ARPFacts) -> [ExpertInfo] {
        guard a.senderIP != 0, a.opcode == 1 || a.opcode == 2 else { return [] }
        defer { arpTable[a.senderIP] = a.senderMAC }
        if let known = arpTable[a.senderIP], known != a.senderMAC {
            return [ExpertInfo(.error, .security,
                               "Duplicate IP \(Fmt.ipv4(a.senderIP)): was \(Fmt.mac(known)), now \(Fmt.mac(a.senderMAC)) — possible ARP spoofing",
                               key: "arp.duplicate-address-detected")]
        }
        return []
    }

    // MARK: Scans

    private func scans(_ ctx: DissectionContext, _ now: Double) -> [ExpertInfo] {
        var out: [ExpertInfo] = []
        if let t = ctx.tcp, t.flags & Transport.TCPFlags.syn != 0, t.flags & Transport.TCPFlags.ack == 0 {
            let n = track(&synTargets, t.srcAddr, "\(t.dstAddr):\(t.dstPort)", now)
            if n > config.scanThreshold {
                out.append(ExpertInfo(.warning, .security, "Possible port scan from \(t.srcAddr) (\(n) targets in \(Int(config.window))s)",
                                      key: "_ns.portscan"))
            }
        }
        if let src = ctx.netSource, let dst = ctx.netDestination,
           ctx.fields["icmp.type"]?.contains(.int(8)) == true || ctx.fields["icmpv6.type"]?.contains(.int(128)) == true {
            let n = track(&pingTargets, src, dst, now)
            if n > config.sweepThreshold {
                out.append(ExpertInfo(.warning, .security, "Possible ping sweep from \(src) (\(n) hosts in \(Int(config.window))s)",
                                      key: "_ns.pingsweep"))
            }
        }
        return out
    }

    /// Sliding-window distinct-target counter.
    private func track(_ table: inout [String: [(Double, String)]], _ src: String, _ target: String, _ now: Double) -> Int {
        var list = table[src, default: []].filter { now - $0.0 <= config.window }
        if !list.contains(where: { $0.1 == target }) { list.append((now, target)) }
        if list.count > config.scanThreshold * 4 { list.removeFirst(list.count - config.scanThreshold * 4) }
        table[src] = list
        return list.count
    }

    private func purge(now: Double) {
        flows = flows.filter { now - $0.value.lastTime < config.flowIdleTimeout }
        synTargets = synTargets.filter { ($0.value.last?.0 ?? 0) > now - config.window }
        pingTargets = pingTargets.filter { ($0.value.last?.0 ?? 0) > now - config.window }
    }
}

/// Dissection + stateful analysis in capture order. Use one instance per capture.
public final class PacketProcessor {
    public let engine = AnomalyEngine()
    public var validateChecksums = false
    public private(set) var count = 0

    public init() {}

    public func reset() { engine.reset(); count = 0 }

    public func process(_ raw: RawPacket) -> CapturedPacket { processWithFields(raw).0 }

    /// Also returns the filter index of the fresh dissection, so a live display filter
    /// can be evaluated without dissecting the packet twice.
    public func processWithFields(_ raw: RawPacket) -> (CapturedPacket, [String: [FieldValue]]) {
        count += 1
        let ctx = Dissector.dissect(raw, number: count, validateChecksums: validateChecksums)
        engine.analyze(ctx, timestamp: raw.timestamp)
        if let tcpInfo = ctx.expert.first(where: { $0.key?.hasPrefix("tcp.analysis") == true && $0.severity >= .warning }) {
            ctx.info = "[\(tcpInfo.message)] " + ctx.info
        }
        return (CapturedPacket(raw: raw, summary: ctx.summary(number: count, raw: raw)), ctx.fields)
    }
}
