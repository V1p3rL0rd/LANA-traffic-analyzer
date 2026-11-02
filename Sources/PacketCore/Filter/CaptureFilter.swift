import Foundation

/// User-facing capture filter: srcaddr / dstaddr / protocols, compiled to a BPF expression.
public struct CaptureFilterSpec: Codable, Equatable, Sendable {
    public var sourceAddresses: String = ""
    public var destinationAddresses: String = ""
    /// Match the conversation in both directions (A→B and B→A).
    public var bidirectional: Bool = false
    public var protocolIDs: Set<String> = []
    public var useCustomBPF: Bool = false
    public var customBPF: String = ""

    public init() {}

    public var isEmpty: Bool {
        useCustomBPF ? customBPF.trimmingCharacters(in: .whitespaces).isEmpty
            : sourceAddresses.isEmpty && destinationAddresses.isEmpty && protocolIDs.isEmpty
    }
}

public enum CaptureFilterError: LocalizedError, Equatable {
    case invalidAddress(String)
    case unknownProtocol(String)

    public var errorDescription: String? {
        switch self {
        case .invalidAddress(let a):
            return "Некорректный адрес «\(a)». Допустимо: IPv4/IPv6, CIDR (10.0.0.0/8), MAC (aa:bb:cc:dd:ee:ff) или имя хоста."
        case .unknownProtocol(let p):
            return "Неизвестный протокол: \(p)"
        }
    }
}

public enum AddressToken: Equatable {
    case host(String)
    case net(String, Int)
    case mac(String)
    case hostname(String)

    /// Strict parsing: anything that is not an address is rejected, so user input
    /// can never inject extra BPF primitives (e.g. "1.2.3.4 or port 22").
    public static func parse(_ raw: String) throws -> AddressToken {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty, s.count <= 253 else { throw CaptureFilterError.invalidAddress(raw) }

        if let slash = s.firstIndex(of: "/") {
            let addr = String(s[..<slash])
            guard let len = Int(s[s.index(after: slash)...]) else { throw CaptureFilterError.invalidAddress(raw) }
            if isIPv4(addr), (0 ... 32).contains(len) { return .net(addr, len) }
            if isIPv6(addr), (0 ... 128).contains(len) { return .net(addr, len) }
            throw CaptureFilterError.invalidAddress(raw)
        }
        if isIPv4(s) || isIPv6(s) { return .host(s) }
        if isMAC(s) { return .mac(s.lowercased().replacingOccurrences(of: "-", with: ":")) }
        if isHostname(s) { return .hostname(s.lowercased()) }
        throw CaptureFilterError.invalidAddress(raw)
    }

    /// `dir` = "src" / "dst" / nil (either direction).
    public func bpf(_ dir: String?) -> String {
        let d = dir.map { $0 + " " } ?? ""
        switch self {
        case .host(let a), .hostname(let a): return "\(d)host \(a)"
        case .net(let a, let l): return "\(d)net \(a)/\(l)"
        case .mac(let m): return "ether \(dir ?? "host") \(m)"
        }
    }

    static func isIPv4(_ s: String) -> Bool {
        var a = in_addr()
        return s.withCString { inet_pton(AF_INET, $0, &a) } == 1
    }

    static func isIPv6(_ s: String) -> Bool {
        var a = in6_addr()
        return s.withCString { inet_pton(AF_INET6, $0, &a) } == 1
    }

    static func isMAC(_ s: String) -> Bool {
        s.range(of: #"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"#, options: .regularExpression) != nil
    }

    /// BPF primitives must never be accepted as host names ("1.2.3.4 or port 22" → reject).
    static let bpfKeywords: Set<String> = [
        "and", "or", "not", "host", "net", "port", "portrange", "src", "dst", "ether", "proto", "ip", "ip6", "arp", "rarp",
        "tcp", "udp", "icmp", "icmp6", "sctp", "igmp", "less", "greater", "broadcast", "multicast", "gateway", "mask",
        "vlan", "mpls", "pppoes", "pppoed", "len", "inbound", "outbound", "type", "subtype", "link", "iso", "decnet",
    ]

    static func isHostname(_ s: String) -> Bool {
        guard !bpfKeywords.contains(s.lowercased()), s.contains(where: { $0.isLetter }) else { return false }
        return s.range(of: #"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"#,
                options: .regularExpression) != nil
    }
}

public enum CaptureFilterBuilder {
    /// Builds a BPF expression; empty string = capture everything.
    public static func build(_ spec: CaptureFilterSpec) throws -> String {
        if spec.useCustomBPF { return spec.customBPF.trimmingCharacters(in: .whitespacesAndNewlines) }

        let src = try tokens(spec.sourceAddresses)
        let dst = try tokens(spec.destinationAddresses)
        var clauses: [String] = []

        switch (src.isEmpty, dst.isEmpty, spec.bidirectional) {
        case (true, true, _):
            break
        case (false, false, true):
            let forward = "(\(orList(src, "src")) and \(orList(dst, "dst")))"
            let reverse = "(\(orList(dst, "src")) and \(orList(src, "dst")))"
            clauses.append("(\(forward) or \(reverse))")
        case (false, true, true):
            clauses.append(orList(src, nil))
        case (true, false, true):
            clauses.append(orList(dst, nil))
        default:
            if !src.isEmpty { clauses.append(orList(src, "src")) }
            if !dst.isEmpty { clauses.append(orList(dst, "dst")) }
        }

        if !spec.protocolIDs.isEmpty {
            let protos = try spec.protocolIDs.sorted().map { id -> String in
                guard let p = ProtocolCatalog.byID[id] else { throw CaptureFilterError.unknownProtocol(id) }
                return p.bpf
            }
            clauses.append(protos.count == 1 ? protos[0] : "(" + protos.joined(separator: " or ") + ")")
        }
        return clauses.joined(separator: " and ")
    }

    static func tokens(_ list: String) throws -> [AddressToken] {
        try list.split(whereSeparator: { $0 == "," || $0 == " " || $0 == ";" })
            .map { try AddressToken.parse(String($0)) }
    }

    private static func orList(_ t: [AddressToken], _ dir: String?) -> String {
        let parts = t.map { $0.bpf(dir) }
        return parts.count == 1 ? parts[0] : "(" + parts.joined(separator: " or ") + ")"
    }
}
