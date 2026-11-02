import CPcap
import Foundation

public enum InterfaceKind: String, Sendable {
    case ethernet = "Ethernet"
    case wifi = "Wi-Fi"
    case loopback = "Loopback"
    case tunnel = "Tunnel / VPN"
    case bridge = "Bridge"
    case wirelessDirect = "AWDL / Wi-Fi Direct"
    case virtual = "Virtual"
    case pseudo = "Pseudo"
    case other = "Other"

    /// SF Symbol name.
    public var symbol: String {
        switch self {
        case .ethernet: "cable.connector"
        case .wifi: "wifi"
        case .loopback: "arrow.triangle.2.circlepath"
        case .tunnel: "lock.shield"
        case .bridge: "point.3.connected.trianglepath.dotted"
        case .wirelessDirect: "antenna.radiowaves.left.and.right"
        case .virtual: "square.stack.3d.up"
        case .pseudo: "rectangle.dashed"
        case .other: "network"
        }
    }
}

public struct NetworkInterface: Identifiable, Hashable, Sendable {
    public var id: String { name }
    public let name: String
    public let details: String
    public let kind: InterfaceKind
    public let addresses: [String]
    public let isUp: Bool
    public let isRunning: Bool

    public var displayName: String {
        let addr = addresses.first.map { " — \($0)" } ?? ""
        return "\(name) (\(kind.rawValue))\(addr)"
    }
}

public enum InterfaceDiscovery {
    // pcap_if_t.flags (pcap.h): stable values since libpcap 1.9.
    private static let ifLoopback: UInt32 = 0x0000_0001
    private static let ifUp: UInt32 = 0x0000_0002
    private static let ifRunning: UInt32 = 0x0000_0004
    private static let ifWireless: UInt32 = 0x0000_0008

    public static func list() throws -> [NetworkInterface] {
        var errbuf = [CChar](repeating: 0, count: 512)
        var head: UnsafeMutablePointer<pcap_if_t>?
        guard pcap_findalldevs(&head, &errbuf) == 0 else {
            throw CaptureError.open(String(cString: errbuf))
        }
        defer { pcap_freealldevs(head) }

        var result: [NetworkInterface] = []
        var cur = head
        while let dev = cur {
            let name = String(cString: dev.pointee.name)
            let desc = dev.pointee.description.map { String(cString: $0) } ?? ""
            let flags = UInt32(dev.pointee.flags)
            var addrs: [String] = []
            var a = dev.pointee.addresses
            while let addr = a {
                if let sa = addr.pointee.addr, let s = numericHost(sa) { addrs.append(s) }
                a = addr.pointee.next
            }
            // IPv4 first, link-local IPv6 last.
            addrs.sort { rank($0) < rank($1) }
            result.append(NetworkInterface(
                name: name, details: desc,
                kind: classify(name, wireless: flags & ifWireless != 0, loopback: flags & ifLoopback != 0),
                addresses: addrs, isUp: flags & ifUp != 0, isRunning: flags & ifRunning != 0))
            cur = dev.pointee.next
        }
        // Active, addressed interfaces first — that is what users pick 95% of the time.
        return result.sorted {
            ($0.isRunning ? 0 : 1, $0.addresses.isEmpty ? 1 : 0, $0.name) < ($1.isRunning ? 0 : 1, $1.addresses.isEmpty ? 1 : 0, $1.name)
        }
    }

    static func classify(_ name: String, wireless: Bool, loopback: Bool) -> InterfaceKind {
        if loopback || name.hasPrefix("lo") { return .loopback }
        func has(_ p: [String]) -> Bool { p.contains { name.hasPrefix($0) } }
        // Name-based classes first: macOS flags awdl0/llw0 as wireless too, but they are not the Wi-Fi uplink.
        if has(["awdl", "llw", "p2p"]) { return .wirelessDirect }
        if has(["utun", "ipsec", "ppp", "gif", "stf", "tun", "tap", "wg", "tailscale"]) { return .tunnel }
        if has(["bridge", "br-", "vmbr"]) { return .bridge }
        if wireless || has(["wl"]) { return .wifi }
        if has(["en", "eth"]) { return .ethernet }
        if has(["vmenet", "vmnet", "vnic", "veth", "docker", "anpi", "ap"]) { return .virtual }
        if has(["pktap", "any", "nflog", "nfqueue", "bluetooth", "dbus", "usbmon"]) { return .pseudo }
        return .other
    }

    private static func rank(_ a: String) -> Int {
        if !a.contains(":") { return 0 }
        return a.lowercased().hasPrefix("fe80") ? 2 : 1
    }

    private static func numericHost(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        let family = Int32(sa.pointee.sa_family)
        let len: Int
        switch family {
        case AF_INET: len = MemoryLayout<sockaddr_in>.size
        case AF_INET6: len = MemoryLayout<sockaddr_in6>.size
        default: return nil
        }
        var host = [CChar](repeating: 0, count: 1025)
        guard getnameinfo(sa, socklen_t(len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: host)
    }
}
