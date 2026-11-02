import Foundation

enum DHCP {
    static let msgTypes = [1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"]

    static func v4(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard end - o >= 240, let op = d.u8(o), let xid = d.be32(o + 4), let ciaddr = d.be32(o + 12),
              let yiaddr = d.be32(o + 16), let chaddr = d.sub(o + 28, 6), d.be32(o + 236) == 0x6382_5363 else { return false }
        let node = ctx.layer("dhcp", "Dynamic Host Configuration Protocol", o, end - o, display: "DHCP")
        ctx.add(node, "Message type: \(op == 1 ? "Boot Request" : "Boot Reply") (\(op))", "dhcp.type", .int(Int64(op)), o, 1)
        ctx.add(node, "Transaction ID: \(Fmt.hex32(xid))", "dhcp.id", .int(Int64(xid)), o + 4, 4)
        ctx.add(node, "Client IP address: \(Fmt.ipv4(ciaddr))", "dhcp.ip.client", .ipv4(ciaddr), o + 12, 4)
        ctx.add(node, "Your (client) IP address: \(Fmt.ipv4(yiaddr))", "dhcp.ip.your", .ipv4(yiaddr), o + 16, 4)
        ctx.add(node, "Client MAC address: \(Fmt.mac(chaddr))", "dhcp.hw.mac_addr", .mac(chaddr), o + 28, 6)

        var p = o + 240
        var msgType = 0
        var hostname: String?
        var serverID: UInt32?
        while p < end, let code = d.u8(p) {
            if code == 255 { break }
            if code == 0 { p += 1; continue }
            guard let len = d.u8(p + 1), p + 2 + Int(len) <= end else { ctx.malformed("DHCP", node, "option overruns packet"); break }
            let v = p + 2
            switch code {
            case 53:
                msgType = Int(d.u8(v) ?? 0)
                ctx.add(node, "Option (53) DHCP Message Type: \(msgTypes[msgType] ?? "?")", "dhcp.option.dhcp", .int(Int64(msgType)), p, 2 + Int(len))
            case 12:
                hostname = String(decoding: d[v ..< v + Int(len)], as: UTF8.self)
                ctx.add(node, "Option (12) Host Name: \(hostname!)", "dhcp.option.hostname", .string(hostname!), p, 2 + Int(len))
            case 50: if let ip = d.be32(v) { ctx.add(node, "Option (50) Requested IP: \(Fmt.ipv4(ip))", "dhcp.option.requested_ip_address", .ipv4(ip), p, 6) }
            case 54: serverID = d.be32(v)
                ctx.add(node, "Option (54) DHCP Server Identifier: \(serverID.map(Fmt.ipv4) ?? "?")", "dhcp.option.dhcp_server_id",
                        .ipv4(serverID ?? 0), p, 2 + Int(len))
            case 51: ctx.add(node, "Option (51) Lease Time: \(d.be32(v) ?? 0) s", "dhcp.option.ip_address_lease_time", .int(Int64(d.be32(v) ?? 0)), p, 6)
            case 3: if let ip = d.be32(v) { ctx.add(node, "Option (3) Router: \(Fmt.ipv4(ip))", "dhcp.option.router", .ipv4(ip), p, 2 + Int(len)) }
            case 6:
                let servers = stride(from: v, to: v + Int(len), by: 4).compactMap { d.be32($0) }.map(Fmt.ipv4)
                ctx.add(node, "Option (6) Domain Name Server: \(servers.joined(separator: ", "))", nil, nil, p, 2 + Int(len))
            case 1: if let m = d.be32(v) { ctx.add(node, "Option (1) Subnet Mask: \(Fmt.ipv4(m))", "dhcp.option.subnet_mask", .ipv4(m), p, 6) }
            default: ctx.add(node, "Option (\(code)) \(len) bytes", "dhcp.option.type", .int(Int64(code)), p, 2 + Int(len))
            }
            p = v + Int(len)
        }
        let typeName = msgTypes[msgType] ?? "BOOTP"
        ctx.setInfo("DHCP \(typeName) - Transaction ID \(Fmt.hex32(xid))\(hostname.map { " (\($0))" } ?? "")")
        if msgType == 6 { ctx.flag(.error, .response, "DHCP NAK — lease refused", key: "dhcp.nak", on: node) }
        if msgType == 4 { ctx.flag(.warning, .response, "DHCP Decline — address conflict detected by client", key: "dhcp.decline", on: node) }
        if msgType == 2 || msgType == 5, let s = serverID { ctx.index("dhcp.server", .ipv4(s)) }
        return true
    }

    static func v6(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let type = d.u8(o), let xid = d.be24(o + 1) else { return false }
        let names = [1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply",
                     8: "Release", 9: "Decline", 10: "Reconfigure", 11: "Information-request", 12: "Relay-forw", 13: "Relay-reply"]
        let node = ctx.layer("dhcpv6", "DHCPv6", o, end - o, display: "DHCPv6")
        ctx.add(node, "Message type: \(names[Int(type)] ?? "?") (\(type))", "dhcpv6.msgtype", .int(Int64(type)), o, 1)
        ctx.add(node, "Transaction ID: \(String(format: "0x%06x", xid))", "dhcpv6.xid", .int(Int64(xid)), o + 1, 3)
        var p = o + 4
        while p + 4 <= end, let code = d.be16(p), let len = d.be16(p + 2) {
            if code == 13, let status = d.be16(p + 4), status != 0 {
                ctx.flag(.error, .response, "DHCPv6 status code \(status)", key: "dhcpv6.status_error", on: node)
            }
            p += 4 + Int(len)
        }
        ctx.setInfo("\(names[Int(type)] ?? "type \(type)") XID: \(String(format: "0x%06x", xid))")
        return true
    }
}
