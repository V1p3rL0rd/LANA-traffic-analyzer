import Foundation

/// TCP facts handed from the stateless dissector to the stateful analyzer.
public struct TCPSegmentFacts: Sendable {
    public let srcAddr: String
    public let dstAddr: String
    public let srcPort: UInt16
    public let dstPort: UInt16
    public let seq: UInt32
    public let ack: UInt32
    public let flags: UInt16
    public let window: UInt16
    public let windowScale: UInt8?   // only present on SYN
    public let payloadLength: Int
}

public struct ARPFacts: Sendable {
    public let opcode: UInt16
    public let senderMAC: [UInt8]
    public let senderIP: UInt32
    public let targetIP: UInt32
}

/// Mutable state of one dissection pass. Dissectors append protocol layers, fields
/// (both tree and filter index), expert info and summary columns.
public final class DissectionContext {
    public let data: [UInt8]
    public let linkType: Int32
    public let validateChecksums: Bool

    public private(set) var tree: [Field] = []
    public private(set) var fields: [String: [FieldValue]] = [:]
    public private(set) var protocols: [String] = []
    public private(set) var expert: [ExpertInfo] = []

    public var source = ""
    public var destination = ""
    public var protocolName = ""
    public var info = ""
    public var netSource: String?
    public var netDestination: String?
    public var tcp: TCPSegmentFacts?
    public var arp: ARPFacts?
    /// Depth guard against crafted tunnel-in-tunnel recursion.
    var encapsulationDepth = 0

    public init(data: [UInt8], linkType: Int32, validateChecksums: Bool) {
        self.data = data
        self.linkType = linkType
        self.validateChecksums = validateChecksums
    }

    // MARK: Layers & fields

    /// Starts a new protocol layer at top level; becomes the "Protocol" column.
    @discardableResult
    public func layer(_ abbrev: String, _ title: String, _ offset: Int, _ length: Int, display: String? = nil) -> Field {
        let node = Field(title, range: clamp(offset, length))
        tree.append(node)
        protocols.append(abbrev)
        fields[abbrev, default: []].append(.bool(true))
        protocolName = display ?? abbrev.uppercased()
        return node
    }

    @discardableResult
    public func add(_ parent: Field, _ label: String, _ key: String? = nil, _ value: FieldValue? = nil,
                    _ offset: Int, _ length: Int) -> Field {
        let node = Field(label, range: clamp(offset, length))
        parent.append(node)
        if let key, let value { fields[key, default: []].append(value) }
        return node
    }

    /// Indexes a value for the display filter without creating a tree node.
    public func index(_ key: String, _ value: FieldValue) {
        fields[key, default: []].append(value)
    }

    public func flag(_ severity: Severity, _ group: ExpertGroup, _ message: String,
                     key: String? = nil, on node: Field? = nil) {
        let e = ExpertInfo(severity, group, message, key: key)
        expert.append(e)
        if let key { fields[key, default: []].append(.bool(true)) }
        if let node {
            node.severity = max(node.severity ?? severity, severity)
            let marker = Field("[Expert Info (\(severity)/\(group.rawValue)): \(message)]", range: node.range, severity: severity)
            node.append(marker)
        }
    }

    /// Appends expert items computed by the stateful analyzers (they are not part of the stateless tree).
    public func merge(_ items: [ExpertInfo]) {
        for e in items where !expert.contains(e) {
            expert.append(e)
            if let key = e.key { fields[key, default: []].append(.bool(true)) }
        }
    }

    /// Adds a top-level "Expert Info" node listing every item (stateless + stored analysis results).
    public func appendExpertTree() {
        guard !expert.isEmpty else { return }
        let top = Field("Expert Info (\(expert.count))", range: nil, severity: expert.map(\.severity).max())
        for e in expert {
            top.append(Field("[\(e.severity)] \(e.group.rawValue): \(e.message)\(e.key.map { "  (\($0))" } ?? "")",
                             range: nil, severity: e.severity))
        }
        tree.append(top)
    }

    public func malformed(_ proto: String, _ node: Field?, _ why: String = "packet too short") {
        flag(.error, .malformed, "Malformed \(proto): \(why)", key: "_ws.malformed", on: node)
        if !info.contains("[Malformed") { info += " [Malformed \(proto)]" }
    }

    public func setInfo(_ s: String) { info = s }

    public func setAddresses(_ src: String, _ dst: String, network: Bool) {
        source = src
        destination = dst
        if network { netSource = src; netDestination = dst }
    }

    public func summary(number: Int, raw: RawPacket) -> PacketSummary {
        PacketSummary(number: number, timestamp: raw.timestamp, source: source, destination: destination,
                      protocolName: protocolName.isEmpty ? "Unknown" : protocolName, length: raw.originalLength,
                      info: info.trimmingCharacters(in: .whitespaces), expert: expert, protocols: protocols)
    }

    private func clamp(_ offset: Int, _ length: Int) -> Range<Int>? {
        guard offset >= 0, length > 0, offset < data.count else { return nil }
        return offset ..< min(data.count, offset + length)
    }
}
