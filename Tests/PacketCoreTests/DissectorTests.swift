import XCTest
@testable import PacketCore

final class DissectorTests: XCTestCase {
    typealias F = Transport.TCPFlags

    func testTCPSynDissection() {
        let ctx = Dissector.dissect(PB.tcpFrame(51000, 443, seq: 1, flags: F.syn), number: 1)
        XCTAssertEqual(ctx.protocols, ["frame", "eth", "ip", "tcp"])
        XCTAssertEqual(ctx.protocolName, "TCP")
        XCTAssertEqual(ctx.source, "10.0.0.1")
        XCTAssertEqual(ctx.destination, "10.0.0.2")
        XCTAssertTrue(ctx.info.contains("[SYN]"), ctx.info)
        XCTAssertEqual(ctx.fields["tcp.dstport"], [.int(443)])
        XCTAssertNotNil(ctx.tcp)
        XCTAssertTrue(ctx.expert.filter { $0.severity >= .warning }.isEmpty, "\(ctx.expert)")
    }

    func testIPv4ChecksumValidation() {
        let ok = Dissector.dissect(PB.tcpFrame(1, 2, seq: 1, flags: F.ack), number: 1, validateChecksums: true)
        XCTAssertFalse(ok.expert.contains { $0.key == "ip.checksum.bad" })
        var bytes = PB.eth(0x0800, PB.ipv4(PB.ipA, PB.ipB, proto: 6, PB.tcp(1, 2, seq: 1, flags: F.ack)))
        bytes[14 + 10] ^= 0xFF
        let bad = Dissector.dissect(PB.raw(bytes), number: 1, validateChecksums: true)
        XCTAssertTrue(bad.expert.contains { $0.key == "ip.checksum.bad" && $0.severity == .error })
    }

    func testRSTAndScanFlagsAreErrors() {
        let rst = Dissector.dissect(PB.tcpFrame(80, 5000, seq: 1, flags: F.rst | F.ack), number: 1)
        XCTAssertTrue(rst.expert.contains { $0.key == "tcp.connection.rst" && $0.severity == .error })
        let xmas = Dissector.dissect(PB.tcpFrame(1, 2, seq: 1, flags: F.fin | F.psh | F.urg), number: 1)
        XCTAssertTrue(xmas.expert.contains { $0.key == "tcp.flags.xmas" })
        let null = Dissector.dissect(PB.tcpFrame(1, 2, seq: 1, flags: 0), number: 1)
        XCTAssertTrue(null.expert.contains { $0.key == "tcp.flags.null" })
    }

    func testLowTTLAndFragmentWarnings() {
        let frame = PB.eth(0x0800, PB.ipv4(PB.ipA, PB.ipB, proto: 17, ttl: 1, frag: 0x2000, PB.udp(1000, 2000, [1, 2, 3, 4])))
        let ctx = Dissector.dissect(PB.raw(frame), number: 1)
        XCTAssertTrue(ctx.expert.contains { $0.key == "ip.ttl.too_small" && $0.severity == .warning })
        XCTAssertTrue(ctx.expert.contains { $0.key == "ip.fragment" && $0.severity == .warning })
    }

    func testDNSResponseCompressionAndNXDOMAIN() {
        let ok = PB.dnsResponse(id: 0xBEEF, name: "example.com", rcode: 0, answer: [93, 184, 216, 34])
        let ctx = Dissector.dissect(PB.raw(PB.eth(0x0800, PB.ipv4(PB.ipB, PB.ipA, proto: 17, PB.udp(53, 40000, ok)))), number: 1)
        XCTAssertEqual(ctx.protocolName, "DNS")
        XCTAssertEqual(ctx.fields["dns.qry.name"], [.string("example.com")])
        XCTAssertEqual(ctx.fields["dns.a"], [.ipv4(0x5DB8_D822)])
        XCTAssertTrue(ctx.info.contains("A 93.184.216.34"), ctx.info)

        let nx = PB.dnsResponse(id: 1, name: "nope.invalid", rcode: 3, answer: nil)
        let c2 = Dissector.dissect(PB.raw(PB.eth(0x0800, PB.ipv4(PB.ipB, PB.ipA, proto: 17, PB.udp(53, 40000, nx)))), number: 1)
        XCTAssertTrue(c2.expert.contains { $0.key == "dns.nxdomain" && $0.severity == .warning })

        let fail = PB.dnsResponse(id: 2, name: "x.test", rcode: 2, answer: nil)
        let c3 = Dissector.dissect(PB.raw(PB.eth(0x0800, PB.ipv4(PB.ipB, PB.ipA, proto: 17, PB.udp(53, 40000, fail)))), number: 1)
        XCTAssertTrue(c3.expert.contains { $0.key == "dns.error" && $0.severity == .error })
    }

    func testDNSCompressionLoopIsRejected() {
        // Name pointer pointing at itself must not hang.
        var msg = PB.be16(1) + PB.be16(0x0100) + PB.be16(1) + PB.be16(0) + PB.be16(0) + PB.be16(0)
        msg += [0xC0, 0x0C] + PB.be16(1) + PB.be16(1)
        let ctx = Dissector.dissect(PB.raw(PB.eth(0x0800, PB.ipv4(PB.ipA, PB.ipB, proto: 17, PB.udp(40000, 53, msg)))), number: 1)
        XCTAssertTrue(ctx.expert.contains { $0.key == "_ws.malformed" })
    }

    func testTLSClientHelloSNI() {
        let ctx = Dissector.dissect(PB.tcpFrame(52000, 443, seq: 1, ack: 1, flags: F.ack | F.psh, PB.tlsClientHello(sni: "api.example.org")), number: 1)
        XCTAssertEqual(ctx.protocolName, "TLS")
        XCTAssertEqual(ctx.fields["tls.handshake.extensions_server_name"], [.string("api.example.org")])
        XCTAssertTrue(ctx.info.contains("Client Hello (SNI=api.example.org)"), ctx.info)
    }

    func testHTTPErrorsAndBasicAuth() {
        let resp = Array("HTTP/1.1 503 Service Unavailable\r\nServer: nginx\r\n\r\n".utf8)
        let c1 = Dissector.dissect(PB.tcpFrame(PB.ipB, PB.ipA, 80, 50000, seq: 1, ack: 1, flags: F.ack | F.psh, resp), number: 1)
        XCTAssertEqual(c1.protocolName, "HTTP")
        XCTAssertTrue(c1.expert.contains { $0.severity == .error && $0.group == .response })

        let req = Array("GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n".utf8)
        let c2 = Dissector.dissect(PB.tcpFrame(50000, 8080, seq: 1, ack: 1, flags: F.ack | F.psh, req), number: 1)
        XCTAssertEqual(c2.fields["http.request.method"], [.string("GET")])
        XCTAssertTrue(c2.expert.contains { $0.key == "http.auth.basic" && $0.severity == .warning })
    }

    func testLoopbackAndRawLinkTypes() {
        let ip = PB.ipv4(PB.ipA, PB.ipB, proto: 6, PB.tcp(1, 2, seq: 1, flags: F.syn))
        let lo = Dissector.dissect(PB.raw([2, 0, 0, 0] + ip, linkType: 0), number: 1)
        XCTAssertEqual(lo.protocols, ["frame", "null", "ip", "tcp"])
        let utun = Dissector.dissect(PB.raw(ip, linkType: 12), number: 1)
        XCTAssertEqual(utun.protocols, ["frame", "ip", "tcp"])
    }

    func testVLANAndARP() {
        let arp = PB.arpReply(senderMAC: PB.macA, senderIP: PB.ipA, targetIP: PB.ipB)
        let tagged = Array(arp[0 ..< 12]) + PB.be16(0x8100) + PB.be16(0x0064) + Array(arp[12...])
        let ctx = Dissector.dissect(PB.raw(tagged), number: 1)
        XCTAssertEqual(ctx.fields["vlan.id"], [.int(100)])
        XCTAssertEqual(ctx.protocolName, "ARP")
        XCTAssertTrue(ctx.info.contains("10.0.0.1 is at 02:00:00:00:00:0a"), ctx.info)
    }

    /// Every truncation of every sample must dissect without trapping.
    func testTruncationFuzzNeverCrashes() {
        let samples: [[UInt8]] = [
            PB.tcpFrame(52000, 443, seq: 1, ack: 1, flags: F.ack | F.psh, PB.tlsClientHello(sni: "a.b")).data,
            PB.eth(0x0800, PB.ipv4(PB.ipB, PB.ipA, proto: 17, PB.udp(53, 1, PB.dnsResponse(id: 1, name: "a.b", rcode: 0, answer: [1, 2, 3, 4])))),
            PB.arpReply(senderMAC: PB.macA, senderIP: PB.ipA, targetIP: PB.ipB),
        ]
        for s in samples {
            for len in 0 ... s.count {
                _ = Dissector.dissect(PB.raw(Array(s.prefix(len))), number: 1, validateChecksums: true)
            }
        }
        var rng = SystemRandomNumberGenerator()
        for _ in 0 ..< 2000 {
            let n = Int.random(in: 0 ... 200, using: &rng)
            let bytes = (0 ..< n).map { _ in UInt8.random(in: 0 ... 255, using: &rng) }
            for lt: Int32 in [0, 1, 12, 105, 113, 127] {
                _ = Dissector.dissect(PB.raw(bytes, linkType: lt), number: 1, validateChecksums: true)
            }
        }
    }
}
