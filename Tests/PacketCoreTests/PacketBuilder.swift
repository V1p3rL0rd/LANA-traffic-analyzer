@testable import PacketCore

/// Minimal frame builders for tests (Ethernet / IPv4 / TCP / UDP / ARP).
/// Built with explicit `append` calls: long `[UInt8] + [UInt8] + …` chains blow up the type checker.
enum PB {
    static let macA: [UInt8] = [0x02, 0, 0, 0, 0, 0x0A]
    static let macB: [UInt8] = [0x02, 0, 0, 0, 0, 0x0B]
    static let ipA: [UInt8] = [10, 0, 0, 1]
    static let ipB: [UInt8] = [10, 0, 0, 2]

    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    static func eth(_ type: UInt16, _ payload: [UInt8], src: [UInt8] = macA, dst: [UInt8] = macB) -> [UInt8] {
        var b: [UInt8] = []
        b.append(contentsOf: dst)
        b.append(contentsOf: src)
        b.append(contentsOf: be16(type))
        b.append(contentsOf: payload)
        return b
    }

    static func ipv4(_ src: [UInt8], _ dst: [UInt8], proto: UInt8, ttl: UInt8 = 64, frag: UInt16 = 0x4000,
                     _ payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x45, 0]
        h.append(contentsOf: be16(UInt16(20 + payload.count)))
        h.append(contentsOf: be16(0x1234))
        h.append(contentsOf: be16(frag))
        h.append(contentsOf: [ttl, proto, 0, 0])
        h.append(contentsOf: src)
        h.append(contentsOf: dst)
        let cs = Checksum.fold(Checksum.sum(h, 0 ..< 20))
        h[10] = UInt8(cs >> 8)
        h[11] = UInt8(cs & 0xFF)
        h.append(contentsOf: payload)
        return h
    }

    static func tcp(_ sp: UInt16, _ dp: UInt16, seq: UInt32, ack: UInt32 = 0, flags: UInt16, win: UInt16 = 65535,
                    _ payload: [UInt8] = []) -> [UInt8] {
        var b: [UInt8] = []
        b.append(contentsOf: be16(sp))
        b.append(contentsOf: be16(dp))
        b.append(contentsOf: be32(seq))
        b.append(contentsOf: be32(ack))
        b.append(contentsOf: be16(0x5000 | flags))
        b.append(contentsOf: be16(win))
        b.append(contentsOf: [0, 0, 0, 0])
        b.append(contentsOf: payload)
        return b
    }

    static func udp(_ sp: UInt16, _ dp: UInt16, _ payload: [UInt8]) -> [UInt8] {
        var b: [UInt8] = []
        b.append(contentsOf: be16(sp))
        b.append(contentsOf: be16(dp))
        b.append(contentsOf: be16(UInt16(8 + payload.count)))
        b.append(contentsOf: [0, 0])
        b.append(contentsOf: payload)
        return b
    }

    static func arpReply(senderMAC: [UInt8], senderIP: [UInt8], targetIP: [UInt8]) -> [UInt8] {
        var p: [UInt8] = []
        p.append(contentsOf: be16(1))
        p.append(contentsOf: be16(0x0800))
        p.append(contentsOf: [6, 4])
        p.append(contentsOf: be16(2))
        p.append(contentsOf: senderMAC)
        p.append(contentsOf: senderIP)
        p.append(contentsOf: macB)
        p.append(contentsOf: targetIP)
        return eth(0x0806, p, src: senderMAC)
    }

    /// TCP frame from ipA to ipB.
    static func tcpFrame(_ sp: UInt16, _ dp: UInt16, seq: UInt32, ack: UInt32 = 0,
                         flags: UInt16, win: UInt16 = 65535, _ payload: [UInt8] = []) -> RawPacket {
        tcpFrame(from: ipA, to: ipB, sp, dp, seq: seq, ack: ack, flags: flags, win: win, payload)
    }

    static func tcpFrame(from src: [UInt8], to dst: [UInt8], _ sp: UInt16, _ dp: UInt16, seq: UInt32, ack: UInt32 = 0,
                         flags: UInt16, win: UInt16 = 65535, _ payload: [UInt8] = []) -> RawPacket {
        let segment = tcp(sp, dp, seq: seq, ack: ack, flags: flags, win: win, payload)
        return raw(eth(0x0800, ipv4(src, dst, proto: 6, segment)))
    }

    static func raw(_ bytes: [UInt8], ts: Double = 1_700_000_000, linkType: Int32 = 1) -> RawPacket {
        RawPacket(timestamp: ts, originalLength: bytes.count, linkType: linkType, data: bytes)
    }

    /// DNS response for `name` with a compressed A answer.
    static func dnsResponse(id: UInt16, name: String, rcode: UInt16, answer: [UInt8]?) -> [UInt8] {
        var q: [UInt8] = []
        for label in name.split(separator: ".") {
            q.append(UInt8(label.utf8.count))
            q.append(contentsOf: Array(label.utf8))
        }
        q.append(0)
        q.append(contentsOf: be16(1))
        q.append(contentsOf: be16(1))

        var msg: [UInt8] = []
        msg.append(contentsOf: be16(id))
        msg.append(contentsOf: be16(0x8180 | rcode))
        msg.append(contentsOf: be16(1))
        msg.append(contentsOf: be16(answer == nil ? 0 : 1))
        msg.append(contentsOf: be16(0))
        msg.append(contentsOf: be16(0))
        msg.append(contentsOf: q)
        if let answer {
            msg.append(contentsOf: [0xC0, 0x0C])
            msg.append(contentsOf: be16(1))
            msg.append(contentsOf: be16(1))
            msg.append(contentsOf: be32(300))
            msg.append(contentsOf: be16(4))
            msg.append(contentsOf: answer)
        }
        return msg
    }

    static func tlsClientHello(sni: String) -> [UInt8] {
        let name = Array(sni.utf8)
        var sniExt: [UInt8] = []
        sniExt.append(contentsOf: be16(0))
        sniExt.append(contentsOf: be16(UInt16(name.count + 5)))
        sniExt.append(contentsOf: be16(UInt16(name.count + 3)))
        sniExt.append(0)
        sniExt.append(contentsOf: be16(UInt16(name.count)))
        sniExt.append(contentsOf: name)

        var body: [UInt8] = []
        body.append(contentsOf: be16(0x0303))
        body.append(contentsOf: [UInt8](repeating: 0xAB, count: 32))
        body.append(0)
        body.append(contentsOf: be16(2))
        body.append(contentsOf: be16(0x1301))
        body.append(contentsOf: [1, 0])
        body.append(contentsOf: be16(UInt16(sniExt.count)))
        body.append(contentsOf: sniExt)

        var hs: [UInt8] = [1]
        hs.append(contentsOf: be32(UInt32(body.count)).dropFirst())
        hs.append(contentsOf: body)

        var rec: [UInt8] = [0x16]
        rec.append(contentsOf: be16(0x0301))
        rec.append(contentsOf: be16(UInt16(hs.count)))
        rec.append(contentsOf: hs)
        return rec
    }
}
