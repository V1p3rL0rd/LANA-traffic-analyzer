@testable import PacketCore

/// Minimal frame builders for tests (Ethernet / IPv4 / TCP / UDP / ARP).
enum PB {
    static let macA: [UInt8] = [0x02, 0, 0, 0, 0, 0x0A]
    static let macB: [UInt8] = [0x02, 0, 0, 0, 0, 0x0B]

    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }

    static func eth(_ type: UInt16, _ payload: [UInt8], src: [UInt8] = macA, dst: [UInt8] = macB) -> [UInt8] {
        dst + src + be16(type) + payload
    }

    static func ipv4(_ src: [UInt8], _ dst: [UInt8], proto: UInt8, ttl: UInt8 = 64, frag: UInt16 = 0x4000,
                     _ payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x45, 0] + be16(UInt16(20 + payload.count)) + be16(0x1234) + be16(frag) + [ttl, proto, 0, 0] + src + dst
        let cs = Checksum.fold(Checksum.sum(h, 0 ..< 20))
        h[10] = UInt8(cs >> 8); h[11] = UInt8(cs & 0xFF)
        return h + payload
    }

    static func tcp(_ sp: UInt16, _ dp: UInt16, seq: UInt32, ack: UInt32 = 0, flags: UInt16, win: UInt16 = 65535,
                    _ payload: [UInt8] = []) -> [UInt8] {
        be16(sp) + be16(dp) + be32(seq) + be32(ack) + be16(0x5000 | flags) + be16(win) + [0, 0, 0, 0] + payload
    }

    static func udp(_ sp: UInt16, _ dp: UInt16, _ payload: [UInt8]) -> [UInt8] {
        be16(sp) + be16(dp) + be16(UInt16(8 + payload.count)) + [0, 0] + payload
    }

    static func arpReply(senderMAC: [UInt8], senderIP: [UInt8], targetIP: [UInt8]) -> [UInt8] {
        eth(0x0806, be16(1) + be16(0x0800) + [6, 4] + be16(2) + senderMAC + senderIP + macB + targetIP, src: senderMAC)
    }

    static let ipA: [UInt8] = [10, 0, 0, 1]
    static let ipB: [UInt8] = [10, 0, 0, 2]

    static func tcpFrame(_ src: [UInt8] = ipA, _ dst: [UInt8] = ipB, _ sp: UInt16, _ dp: UInt16, seq: UInt32, ack: UInt32 = 0,
                         flags: UInt16, win: UInt16 = 65535, _ payload: [UInt8] = []) -> RawPacket {
        raw(eth(0x0800, ipv4(src, dst, proto: 6, tcp(sp, dp, seq: seq, ack: ack, flags: flags, win: win, payload))))
    }

    static func raw(_ bytes: [UInt8], ts: Double = 1_700_000_000, linkType: Int32 = 1) -> RawPacket {
        RawPacket(timestamp: ts, originalLength: bytes.count, linkType: linkType, data: bytes)
    }

    /// DNS response for `name` with a compressed A answer.
    static func dnsResponse(id: UInt16, name: String, rcode: UInt16, answer: [UInt8]?) -> [UInt8] {
        var q: [UInt8] = []
        for label in name.split(separator: ".") { q.append(UInt8(label.utf8.count)); q += Array(label.utf8) }
        q += [0] + be16(1) + be16(1)
        var msg = be16(id) + be16(0x8180 | rcode) + be16(1) + be16(answer == nil ? 0 : 1) + be16(0) + be16(0) + q
        if let answer { msg += [0xC0, 0x0C] + be16(1) + be16(1) + be32(300) + be16(4) + answer }
        return msg
    }

    static func tlsClientHello(sni: String) -> [UInt8] {
        let name = Array(sni.utf8)
        let sniExt = be16(0) + be16(UInt16(name.count + 5)) + be16(UInt16(name.count + 3)) + [0] + be16(UInt16(name.count)) + name
        let exts = be16(UInt16(sniExt.count)) + sniExt
        let body = be16(0x0303) + [UInt8](repeating: 0xAB, count: 32) + [0] + be16(2) + be16(0x1301) + [1, 0] + exts
        let hs: [UInt8] = [1] + Array(be32(UInt32(body.count)).dropFirst()) + body
        return [0x16] + be16(0x0301) + be16(UInt16(hs.count)) + hs
    }
}
