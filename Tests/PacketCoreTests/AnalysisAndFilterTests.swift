import Foundation
import XCTest
@testable import PacketCore

final class AnomalyEngineTests: XCTestCase {
    typealias F = Transport.TCPFlags

    private func keys(_ p: CapturedPacket) -> Set<String> { Set(p.summary.expert.compactMap(\.key)) }

    func testRetransmissionDupAckAndFastRetransmit() {
        let proc = PacketProcessor()
        let payload = [UInt8](repeating: 0x41, count: 100)
        var t = 1_700_000_000.0
        func next(_ p: RawPacket) -> CapturedPacket {
            t += 0.01
            return proc.process(RawPacket(timestamp: t, originalLength: p.originalLength, linkType: 1, data: p.data))
        }
        _ = next(PB.tcpFrame(40000, 80, seq: 1000, ack: 1, flags: F.ack, payload))
        let seg2 = next(PB.tcpFrame(40000, 80, seq: 1100, ack: 1, flags: F.ack, payload))
        XCTAssertTrue(keys(seg2).isDisjoint(with: ["tcp.analysis.retransmission"]))

        // Receiver ACKs 1100 three times → dup acks
        _ = next(PB.tcpFrame(from: PB.ipB, to: PB.ipA, 80, 40000, seq: 1, ack: 1100, flags: F.ack))
        let d1 = next(PB.tcpFrame(from: PB.ipB, to: PB.ipA, 80, 40000, seq: 1, ack: 1100, flags: F.ack))
        let d2 = next(PB.tcpFrame(from: PB.ipB, to: PB.ipA, 80, 40000, seq: 1, ack: 1100, flags: F.ack))
        XCTAssertTrue(keys(d1).contains("tcp.analysis.duplicate_ack"))
        XCTAssertTrue(keys(d2).contains("tcp.analysis.duplicate_ack"))
        XCTAssertEqual(d2.summary.severity, .warning)

        // Sender resends 1100 → fast retransmission (≥2 dup acks for that seq)
        let rtx = next(PB.tcpFrame(40000, 80, seq: 1100, ack: 1, flags: F.ack, payload))
        XCTAssertTrue(keys(rtx).contains("tcp.analysis.fast_retransmission"), "\(rtx.summary.expert)")
        XCTAssertTrue(rtx.summary.info.hasPrefix("[TCP Fast Retransmission]"))
    }

    func testLostSegmentAndZeroWindow() {
        let proc = PacketProcessor()
        let data = [UInt8](repeating: 0, count: 50)
        _ = proc.process(PB.tcpFrame(40000, 80, seq: 1, ack: 1, flags: F.ack, data))
        let gap = proc.process(PB.tcpFrame(40000, 80, seq: 500, ack: 1, flags: F.ack, data))
        XCTAssertTrue(keys(gap).contains("tcp.analysis.lost_segment"))
        let zw = proc.process(PB.tcpFrame(from: PB.ipB, to: PB.ipA, 80, 40000, seq: 1, ack: 550, flags: F.ack, win: 0))
        XCTAssertTrue(keys(zw).contains("tcp.analysis.zero_window"))
        XCTAssertEqual(zw.summary.severity, .error)
    }

    func testSequenceWraparoundIsNotLoss() {
        let proc = PacketProcessor()
        let data = [UInt8](repeating: 0, count: 16)
        _ = proc.process(PB.tcpFrame(1, 2, seq: UInt32.max - 7, ack: 1, flags: F.ack, data))
        let wrapped = proc.process(PB.tcpFrame(1, 2, seq: 8, ack: 1, flags: F.ack, data))
        XCTAssertFalse(keys(wrapped).contains("tcp.analysis.lost_segment"), "\(wrapped.summary.expert)")
        XCTAssertFalse(keys(wrapped).contains("tcp.analysis.retransmission"))
    }

    func testARPSpoofingDetection() {
        let proc = PacketProcessor()
        let evil: [UInt8] = [0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01]
        let first = proc.process(PB.raw(PB.arpReply(senderMAC: PB.macA, senderIP: [192, 168, 1, 1], targetIP: PB.ipB)))
        XCTAssertNotEqual(first.summary.severity, .error)
        let second = proc.process(PB.raw(PB.arpReply(senderMAC: evil, senderIP: [192, 168, 1, 1], targetIP: PB.ipB)))
        XCTAssertTrue(keys(second).contains("arp.duplicate-address-detected"))
        XCTAssertEqual(second.summary.severity, .error)
    }

    func testPortScanHeuristic() {
        let proc = PacketProcessor()
        var last: CapturedPacket?
        for port in UInt16(1) ... 150 {
            last = proc.process(PB.tcpFrame(55555, port, seq: 7, flags: F.syn))
        }
        XCTAssertTrue(keys(last!).contains("_ns.portscan"))
    }
}

final class FilterTests: XCTestCase {
    func testCaptureFilterBuilder() throws {
        var spec = CaptureFilterSpec()
        spec.sourceAddresses = "10.0.0.1, 192.168.0.0/16"
        spec.destinationAddresses = "8.8.8.8"
        XCTAssertEqual(try CaptureFilterBuilder.build(spec), "(src host 10.0.0.1 or src net 192.168.0.0/16) and dst host 8.8.8.8")

        spec.bidirectional = true
        spec.sourceAddresses = "10.0.0.1"
        XCTAssertEqual(try CaptureFilterBuilder.build(spec),
                       "((src host 10.0.0.1 and dst host 8.8.8.8) or (src host 8.8.8.8 and dst host 10.0.0.1))")

        spec = CaptureFilterSpec()
        spec.sourceAddresses = "aa-bb-cc-dd-ee-ff"
        spec.protocolIDs = ["dns", "arp"]
        XCTAssertEqual(try CaptureFilterBuilder.build(spec),
                       "ether src aa:bb:cc:dd:ee:ff and (arp or ((tcp and (port 53)) or (udp and (port 53))))")
    }

    func testCaptureFilterRejectsInjection() {
        var spec = CaptureFilterSpec()
        spec.sourceAddresses = "1.2.3.4 or port 22"
        XCTAssertThrowsError(try CaptureFilterBuilder.build(spec))
        spec.sourceAddresses = "10.0.0.0/33"
        XCTAssertThrowsError(try CaptureFilterBuilder.build(spec))
        spec.sourceAddresses = "host;rm"
        XCTAssertThrowsError(try CaptureFilterBuilder.build(spec))
    }

    func testEveryCatalogProtocolCompilesToValidBPF() {
        for p in ProtocolCatalog.all where !p.id.hasPrefix("wlan") {
            XCTAssertNil(BPFValidator.validate(p.bpf, linkType: 1), "\(p.id): \(p.bpf)")
        }
        for p in ProtocolCatalog.all where p.id.hasPrefix("wlan") {
            XCTAssertNil(BPFValidator.validate(p.bpf, linkType: 127), "\(p.id): \(p.bpf)")
        }
        XCTAssertEqual(Set(ProtocolCatalog.all.map(\.id)).count, ProtocolCatalog.all.count, "duplicate protocol ids")
        XCTAssertNotNil(BPFValidator.validate("tcp port", linkType: 1))
    }

    func testDisplayFilterEvaluation() throws {
        let proc = PacketProcessor()
        let pkt = proc.process(PB.tcpFrame(51000, 443, seq: 1, flags: Transport.TCPFlags.syn))
        let fields = Dissector.dissect(pkt.raw, number: 1).fields
        func eval(_ s: String) throws -> Bool {
            try DisplayFilter(s).matches(DisplayFilter.lookup(summary: pkt.summary, fields: fields))
        }
        XCTAssertTrue(try eval("tcp"))
        XCTAssertTrue(try eval("ip.addr == 10.0.0.0/8 && tcp.port == 443"))
        XCTAssertTrue(try eval("tcp.port in {80 443}"))
        XCTAssertTrue(try eval("tcp.flags.syn == 1 and not udp"))
        XCTAssertTrue(try eval("ip.src == 10.0.0.1 || dns"))
        XCTAssertFalse(try eval("ip.dst == 10.0.0.1"))
        XCTAssertFalse(try eval("ip.addr != 10.0.0.1"))
        XCTAssertTrue(try eval("tcp.dstport >= 400 && tcp.dstport < 0x200"))
        XCTAssertFalse(try eval("expert.error"))
        XCTAssertTrue(try eval("!(udp || arp)"))
        XCTAssertThrowsError(try DisplayFilter("ip.addr =="))
        XCTAssertThrowsError(try DisplayFilter("(tcp"))
        XCTAssertFalse(try DisplayFilter("dns || expert.error").needsFields)
        XCTAssertTrue(try DisplayFilter("ip.src == 1.2.3.4").needsFields)
    }

    func testIPv6Formatting() {
        var ll: [UInt8] = [0xfe, 0x80]
        ll.append(contentsOf: [UInt8](repeating: 0, count: 13))
        ll.append(1)
        XCTAssertEqual(Fmt.ipv6(ll), "fe80::1")
        XCTAssertEqual(Fmt.ipv6([UInt8](repeating: 0, count: 16)), "::")
        XCTAssertEqual(Fmt.ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), "2001:db8:1::1")
    }
}

final class PcapFileTests: XCTestCase {
    func testRoundTrip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("lana-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let packets = (0 ..< 10).map { i in
            PB.tcpFrame(UInt16(1000 + i), 80, seq: UInt32(i), flags: Transport.TCPFlags.syn)
        }.enumerated().map { i, p in
            RawPacket(timestamp: 1_700_000_000.123456 + Double(i), originalLength: p.originalLength, linkType: 1, data: p.data)
        }
        try PcapFile.write(packets, to: url)
        let back = try PcapFile.read(url)
        XCTAssertEqual(back.count, 10)
        XCTAssertEqual(back[3].data, packets[3].data)
        XCTAssertEqual(back[3].timestamp, packets[3].timestamp, accuracy: 1e-6)
        XCTAssertEqual(back[0].linkType, 1)
    }
}
