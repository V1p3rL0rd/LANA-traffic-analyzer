import Foundation

/// Raw frame as delivered by libpcap (live or offline).
public struct RawPacket: Sendable {
    public let timestamp: Double      // seconds since epoch, µs precision
    public let capturedLength: Int
    public let originalLength: Int
    public let linkType: Int32        // DLT_* / LINKTYPE_*
    public let data: [UInt8]

    public init(timestamp: Double, originalLength: Int, linkType: Int32, data: [UInt8]) {
        self.timestamp = timestamp
        self.capturedLength = data.count
        self.originalLength = originalLength
        self.linkType = linkType
        self.data = data
    }

    public var isTruncatedBySnaplen: Bool { capturedLength < originalLength }
}

public enum Severity: Int, Comparable, Sendable, CustomStringConvertible {
    case note = 1, warning = 2, error = 3
    public static func < (l: Severity, r: Severity) -> Bool { l.rawValue < r.rawValue }
    public var description: String {
        switch self { case .note: "note"; case .warning: "warning"; case .error: "error" }
    }
}

public enum ExpertGroup: String, Sendable, CaseIterable {
    case malformed = "Malformed"
    case checksum = "Checksum"
    case sequence = "Sequence"
    case protocolError = "Protocol"
    case response = "Response"
    case security = "Security"
    case performance = "Performance"
}

/// Wireshark-style "expert info" item. `key` is exposed to the display filter
/// (e.g. `tcp.analysis.retransmission`).
public struct ExpertInfo: Sendable, Hashable {
    public let severity: Severity
    public let group: ExpertGroup
    public let message: String
    public let key: String?

    public init(_ severity: Severity, _ group: ExpertGroup, _ message: String, key: String? = nil) {
        self.severity = severity
        self.group = group
        self.message = message
        self.key = key
    }
}

/// Typed value of a dissected field, used by the display filter engine.
public enum FieldValue: Sendable, Hashable {
    case int(Int64)
    case string(String)
    case ipv4(UInt32)
    case ipv6([UInt8])
    case mac([UInt8])
    case bool(Bool)
    case bytes([UInt8])

    public var displayString: String {
        switch self {
        case .int(let v): return String(v)
        case .string(let s): return s
        case .ipv4(let v): return Fmt.ipv4(v)
        case .ipv6(let b): return Fmt.ipv6(b)
        case .mac(let b): return Fmt.mac(b)
        case .bool(let b): return b ? "1" : "0"
        case .bytes(let b): return Fmt.hex(b, sep: ":")
        }
    }
}

/// Node of the protocol tree shown in the detail pane.
public final class Field: Identifiable {
    public var id: ObjectIdentifier { ObjectIdentifier(self) }
    public var label: String
    public let range: Range<Int>?
    public var children: [Field]?
    public var severity: Severity?

    public init(_ label: String, range: Range<Int>?, severity: Severity? = nil) {
        self.label = label
        self.range = range
        self.severity = severity
    }

    func append(_ child: Field) {
        if children == nil { children = [] }
        children!.append(child)
    }
}

/// Lightweight per-packet record kept for the whole capture (the tree is rebuilt on demand).
public struct PacketSummary: Sendable {
    public let number: Int
    public let timestamp: Double
    public let source: String
    public let destination: String
    public let protocolName: String
    public let length: Int
    public let info: String
    public let expert: [ExpertInfo]
    public let protocols: [String]

    public var severity: Severity? {
        expert.map(\.severity).filter { $0 >= .warning }.max()
    }
}

public struct CapturedPacket: Sendable {
    public let raw: RawPacket
    public let summary: PacketSummary
}
