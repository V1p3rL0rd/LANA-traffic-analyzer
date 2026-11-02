import Foundation

enum Misc {
    static func ntp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard end - o >= 48, let b = d.u8(o), let stratum = d.u8(o + 1) else { return false }
        let li = b >> 6, ver = (b >> 3) & 7, mode = b & 7
        let modes = ["reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast", "control", "private"]
        let node = ctx.layer("ntp", "Network Time Protocol (NTP Version \(ver), \(modes[Int(mode)]))", o, end - o, display: "NTP")
        ctx.add(node, "Leap Indicator: \(li)", "ntp.flags.li", .int(Int64(li)), o, 1)
        ctx.add(node, "Mode: \(modes[Int(mode)])", "ntp.flags.mode", .int(Int64(mode)), o, 1)
        ctx.add(node, "Stratum: \(stratum)", "ntp.stratum", .int(Int64(stratum)), o + 1, 1)
        ctx.setInfo("NTP Version \(ver), \(modes[Int(mode)])")
        if mode == 4, li == 3 || stratum == 0 {
            ctx.flag(.warning, .response, "NTP server unsynchronized (LI=3 / stratum 0 — Kiss-o'-Death?)", key: "ntp.unsync", on: node)
        }
        if mode == 7 || mode == 6 {
            ctx.flag(.warning, .security, "NTP control/private mode (monlist amplification vector)", key: "ntp.control", on: node)
        }
        return true
    }

    /// Minimal BER walk: version + community + PDU type.
    static func snmp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard d.u8(o) == 0x30 else { return false }
        func tlv(_ p: Int) -> (tag: UInt8, len: Int, value: Int)? {
            guard let tag = d.u8(p), let l0 = d.u8(p + 1) else { return nil }
            if l0 & 0x80 == 0 { return (tag, Int(l0), p + 2) }
            let n = Int(l0 & 0x7F)
            guard n <= 3, let bytes = d.sub(p + 2, n) else { return nil }
            return (tag, bytes.reduce(0) { $0 << 8 | Int($1) }, p + 2 + n)
        }
        guard let seq = tlv(o), let ver = tlv(seq.value), ver.tag == 0x02, let verV = d.u8(ver.value) else { return false }
        let node = ctx.layer("snmp", "Simple Network Management Protocol", o, end - o, display: "SNMP")
        let vname = ["v1", "v2c", "v2u", "v3"][min(Int(verV), 3)]
        ctx.add(node, "Version: \(vname) (\(verV))", "snmp.version", .int(Int64(verV)), ver.value, ver.len)
        var info = "SNMP \(vname)"
        if verV < 3, let comm = tlv(ver.value + ver.len), comm.tag == 0x04, let cb = d.sub(comm.value, comm.len) {
            let community = String(decoding: cb, as: UTF8.self)
            ctx.add(node, "Community: \(community)", "snmp.community", .string(community), comm.value, comm.len)
            ctx.flag(.warning, .security, "SNMP \(vname) community string in cleartext", key: "snmp.cleartext_community", on: node)
            if ["public", "private"].contains(community) {
                ctx.flag(.warning, .security, "Default SNMP community '\(community)'", key: "snmp.default_community", on: node)
            }
            if let pdu = d.u8(comm.value + comm.len) {
                let pdus: [UInt8: String] = [0xA0: "get-request", 0xA1: "get-next-request", 0xA2: "get-response", 0xA3: "set-request",
                                             0xA4: "trap", 0xA5: "getBulkRequest", 0xA6: "inform-request", 0xA7: "snmpV2-trap", 0xA8: "report"]
                info = pdus[pdu] ?? "PDU \(Fmt.hex8(pdu))"
                ctx.index("snmp.pdu_type", .int(Int64(pdu)))
                // error-status lives after request-id inside the PDU
                if pdu == 0xA2, let p = tlv(comm.value + comm.len), let rid = tlv(p.value), let es = tlv(rid.value + rid.len),
                   let status = d.u8(es.value), status != 0 {
                    ctx.flag(.error, .response, "SNMP error-status \(status)", key: "snmp.error_status", on: node)
                    info += " error-status=\(status)"
                }
            }
        }
        ctx.setInfo(info)
        return true
    }

    static func syslog(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard d.u8(o) == 0x3C, let close = (o + 1 ..< min(end, o + 5)).first(where: { d[$0] == 0x3E }),
              let pri = Int(String(decoding: d[(o + 1) ..< close], as: UTF8.self)) else { return false }
        let sev = pri & 7, fac = pri >> 3
        let sevNames = ["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]
        let node = ctx.layer("syslog", "Syslog message", o, end - o, display: "Syslog")
        ctx.add(node, "Facility: \(fac), Severity: \(sevNames[sev])", "syslog.level", .int(Int64(sev)), o, close - o + 1)
        let msg = String(decoding: d[(close + 1) ..< end].prefix(300), as: UTF8.self)
        ctx.add(node, "Message: \(msg)", "syslog.msg", .string(msg), close + 1, end - close - 1)
        ctx.setInfo("\(sevNames[sev]): \(msg)")
        if sev <= 3 { ctx.flag(.error, .response, "Syslog severity \(sevNames[sev])", key: "syslog.error", on: node) }
        else if sev == 4 { ctx.flag(.warning, .response, "Syslog WARNING", key: "syslog.warning", on: node) }
        return true
    }

    static func tftp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let op = d.be16(o), (1 ... 6).contains(op) else { return false }
        let names = [1: "Read Request", 2: "Write Request", 3: "Data Packet", 4: "Acknowledgement", 5: "Error Code", 6: "Option Ack"]
        let node = ctx.layer("tftp", "Trivial File Transfer Protocol", o, end - o, display: "TFTP")
        ctx.add(node, "Opcode: \(names[Int(op)]!)", "tftp.opcode", .int(Int64(op)), o, 2)
        var info = names[Int(op)]!
        if op <= 2 {
            var e = o + 2
            while e < end, d[e] != 0 { e += 1 }
            let file = String(decoding: d[(o + 2) ..< e], as: UTF8.self)
            info += ", File: \(file)"
            ctx.index("tftp.source_file", .string(file))
        } else if op == 3 || op == 4 {
            info += ", Block: \(d.be16(o + 2) ?? 0)"
        } else if op == 5 {
            let code = d.be16(o + 2) ?? 0
            info += ", Code: \(code)"
            ctx.flag(.error, .response, "TFTP error \(code)", key: "tftp.error", on: node)
        }
        ctx.setInfo(info)
        return true
    }

    static func wireguard(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let t = d.u8(o), (1 ... 4).contains(t), d.u8(o + 1) == 0, d.u8(o + 2) == 0, d.u8(o + 3) == 0 else { return false }
        let names = [1: "Handshake Initiation", 2: "Handshake Response", 3: "Cookie Reply", 4: "Transport Data"]
        let node = ctx.layer("wg", "WireGuard Protocol", o, end - o, display: "WireGuard")
        ctx.add(node, "Type: \(names[Int(t)]!) (\(t))", "wg.type", .int(Int64(t)), o, 1)
        if let s = d.le32(o + 4) { ctx.add(node, "Sender/Receiver: \(Fmt.hex32(s))", "wg.sender", .int(Int64(s)), o + 4, 4) }
        ctx.setInfo(names[Int(t)]!)
        if t == 3 { ctx.flag(.warning, .performance, "WireGuard cookie reply (responder under load / DoS mitigation)", key: "wg.cookie", on: node) }
        return true
    }

    static func vxlan(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let flags = d.u8(o), flags & 0x08 != 0, let vni = d.be24(o + 4) else { return false }
        let node = ctx.layer("vxlan", "Virtual eXtensible Local Area Network, VNI: \(vni)", o, 8, display: "VXLAN")
        ctx.add(node, "VNI: \(vni)", "vxlan.vni", .int(Int64(vni)), o + 4, 3)
        ctx.encapsulationDepth += 1
        Dissector.ethernet(ctx, o + 8)
        ctx.info = "[VXLAN \(vni)] " + ctx.info
        return true
    }

    static func geneve(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let vl = d.u8(o), vl >> 6 == 0, let ptype = d.be16(o + 2), let vni = d.be24(o + 4) else { return false }
        let optLen = Int(vl & 0x3F) * 4
        let node = ctx.layer("geneve", "Generic Network Virtualization Encapsulation, VNI: \(vni)", o, 8 + optLen, display: "Geneve")
        ctx.add(node, "VNI: \(vni)", "geneve.vni", .int(Int64(vni)), o + 4, 3)
        ctx.encapsulationDepth += 1
        if ptype == 0x6558 { Dissector.ethernet(ctx, o + 8 + optLen) } else { Dissector.etherType(ctx, ptype, o + 8 + optLen) }
        return true
    }

    static func rip(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let cmd = d.u8(o), let ver = d.u8(o + 1), cmd == 1 || cmd == 2 else { return false }
        let node = ctx.layer("rip", "Routing Information Protocol", o, end - o, display: "RIPv\(ver)")
        let routes = (end - o - 4) / 20
        ctx.add(node, "Command: \(cmd == 1 ? "Request" : "Response"), Version \(ver), \(routes) entries", "rip.command", .int(Int64(cmd)), o, 2)
        ctx.setInfo("\(cmd == 1 ? "Request" : "Response") (\(routes) routes)")
        if ver == 2, d.be16(o + 4) == 0xFFFF, d.be16(o + 6) == 2 {
            ctx.flag(.warning, .security, "RIPv2 simple password authentication (cleartext)", key: "rip.auth.cleartext", on: node)
        }
        if ver == 1 { ctx.flag(.note, .security, "RIPv1 has no authentication", on: node) }
        return true
    }

    static func stun(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let type = d.be16(o), type & 0xC000 == 0, d.be32(o + 4) == 0x2112_A442 else { return false }
        let method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
        let cls = ((type & 0x0100) >> 7) | ((type & 0x0010) >> 4)
        let classes = ["Request", "Indication", "Success Response", "Error Response"]
        let methods: [UInt16: String] = [1: "Binding", 3: "Allocate", 4: "Refresh", 6: "Send", 7: "Data", 8: "CreatePermission", 9: "ChannelBind"]
        let node = ctx.layer("stun", "Session Traversal Utilities for NAT", o, end - o, display: "STUN")
        ctx.add(node, "Message Type: \(methods[method] ?? "method \(method)") \(classes[Int(cls)])", "stun.type", .int(Int64(type)), o, 2)
        ctx.setInfo("\(methods[method] ?? "method \(method)") \(classes[Int(cls)])")
        if cls == 3 { ctx.flag(.warning, .response, "STUN error response", key: "stun.error", on: node) }
        return true
    }

    static func ike(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        var p = o
        if let marker = d.be32(o), marker == 0, isNATTPort(ctx) { p += 4 }        // NAT-T non-ESP marker
        else if d.u8(o) == 0xFF, end - o == 1 { ctx.layer("isakmp", "NAT-keepalive", o, 1, display: "ISAKMP"); ctx.setInfo("NAT-keepalive"); return true }
        guard end - p >= 28, let ver = d.u8(p + 17), let exch = d.u8(p + 18) else {
            if isNATTPort(ctx) { IP.esp(ctx, o, end); return true }    // ESP-in-UDP
            return false
        }
        let exchanges: [UInt8: String] = [2: "Identity Protection (Main Mode)", 4: "Aggressive", 5: "Informational", 32: "Quick Mode",
                                          34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"]
        let node = ctx.layer("isakmp", "Internet Security Association and Key Management Protocol", p, end - p, display: "ISAKMP")
        ctx.add(node, "Version: \(ver >> 4).\(ver & 0xF)", "isakmp.version", .int(Int64(ver)), p + 17, 1)
        ctx.add(node, "Exchange type: \(exchanges[exch] ?? String(exch))", "isakmp.exchtype", .int(Int64(exch)), p + 18, 1)
        ctx.setInfo(exchanges[exch] ?? "Exchange \(exch)")
        if exch == 4 { ctx.flag(.warning, .security, "IKEv1 Aggressive Mode (PSK hash exposure)", key: "isakmp.aggressive", on: node) }
        return true
    }

    private static func isNATTPort(_ ctx: DissectionContext) -> Bool {
        ctx.fields["udp.port"]?.contains(.int(4500)) ?? false
    }

    static func radius(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let code = d.u8(o), let id = d.u8(o + 1), let len = d.be16(o + 2), len >= 20 else { return false }
        let codes = [1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request", 5: "Accounting-Response",
                     11: "Access-Challenge", 40: "Disconnect-Request", 43: "CoA-Request"]
        let node = ctx.layer("radius", "RADIUS Protocol", o, end - o, display: "RADIUS")
        ctx.add(node, "Code: \(codes[Int(code)] ?? "?") (\(code))", "radius.code", .int(Int64(code)), o, 1)
        ctx.setInfo("\(codes[Int(code)] ?? "Code \(code)") id=\(id)")
        if code == 3 { ctx.flag(.error, .response, "RADIUS Access-Reject", key: "radius.reject", on: node) }
        return true
    }

    static func bfd(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let b0 = d.u8(o), let b1 = d.u8(o + 1), b0 >> 5 == 1 else { return false }
        let state = b1 >> 6, diag = b0 & 0x1F
        let states = ["AdminDown", "Down", "Init", "Up"]
        let node = ctx.layer("bfd", "Bidirectional Forwarding Detection", o, end - o, display: "BFD")
        ctx.add(node, "State: \(states[Int(state)]), Diag: \(diag)", "bfd.sta", .int(Int64(state)), o, 2)
        ctx.setInfo("Diag: \(diag), State: \(states[Int(state)])")
        if state <= 1 { ctx.flag(.error, .protocolError, "BFD session \(states[Int(state)]) (diag \(diag))", key: "bfd.down", on: node) }
        return true
    }

    static func bgp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let marker = d.sub(o, 16), marker.allSatisfy({ $0 == 0xFF }) else {
            ctx.layer("bgp", "Border Gateway Protocol (continuation)", o, end - o, display: "BGP"); return true
        }
        let node = ctx.layer("bgp", "Border Gateway Protocol", o, end - o, display: "BGP")
        var p = o, msgs: [String] = []
        let names: [UInt8: String] = [1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"]
        while p + 19 <= end, let len = d.be16(p + 16), let type = d.u8(p + 18), len >= 19, msgs.count < 64 {
            let n = names[type] ?? "type \(type)"
            msgs.append(n)
            let m = ctx.add(node, "\(n) Message (\(len) bytes)", "bgp.type", .int(Int64(type)), p, Int(len))
            if type == 3, let code = d.u8(p + 19), let sub = d.u8(p + 20) {
                ctx.flag(.error, .protocolError, "BGP NOTIFICATION code \(code)/\(sub) — session torn down", key: "bgp.notification", on: m)
            }
            p += Int(len)
        }
        ctx.setInfo(msgs.joined(separator: ", ") + " Message")
        return true
    }

    static func mqtt(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let b = d.u8(o) else { return false }
        let types = ["Reserved", "Connect Command", "Connect Ack", "Publish Message", "Publish Ack", "Publish Received",
                     "Publish Release", "Publish Complete", "Subscribe Request", "Subscribe Ack", "Unsubscribe Request",
                     "Unsubscribe Ack", "Ping Request", "Ping Response", "Disconnect Req", "Auth"]
        let t = Int(b >> 4)
        let node = ctx.layer("mqtt", "MQ Telemetry Transport Protocol, \(types[t])", o, end - o, display: "MQTT")
        ctx.add(node, "Message Type: \(types[t]) (\(t))", "mqtt.msgtype", .int(Int64(t)), o, 1)
        ctx.setInfo(types[t])
        if t == 2, let rc = d.u8(o + 3), rc != 0 {
            ctx.flag(.error, .response, "MQTT CONNACK refused (rc=\(rc))", key: "mqtt.conack.refused", on: node)
        }
        return true
    }

    static func modbus(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let tid = d.be16(o), d.be16(o + 2) == 0, let unit = d.u8(o + 6), let fc = d.u8(o + 7) else { return false }
        let names: [UInt8: String] = [1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
                                      5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils", 16: "Write Multiple Registers"]
        let node = ctx.layer("modbus", "Modbus/TCP", o, end - o, display: "Modbus/TCP")
        let base = fc & 0x7F
        ctx.add(node, "Transaction: \(tid), Unit: \(unit), Function: \(names[base] ?? String(base))", "modbus.func_code", .int(Int64(base)), o, 8)
        ctx.setInfo("\(fc & 0x80 != 0 ? "Exception: " : "")\(names[base] ?? "Function \(base)") (unit \(unit))")
        if fc & 0x80 != 0 {
            ctx.flag(.error, .response, "Modbus exception code \(d.u8(o + 8) ?? 0)", key: "modbus.exception", on: node)
        } else if [5, 6, 15, 16].contains(base) {
            ctx.flag(.note, .security, "Modbus write operation", key: "modbus.write", on: node)
        }
        return true
    }

    static func kafka(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        guard let len = d.be32(o), len < 100_000_000, let apiKey = d.be16(o + 4), let apiVer = d.be16(o + 6), apiKey < 100 else { return false }
        let apis: [UInt16: String] = [0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 8: "OffsetCommit", 9: "OffsetFetch",
                                      10: "FindCoordinator", 11: "JoinGroup", 12: "Heartbeat", 13: "LeaveGroup", 14: "SyncGroup", 18: "ApiVersions"]
        let node = ctx.layer("kafka", "Kafka", o, end - o, display: "Kafka")
        ctx.add(node, "API Key: \(apis[apiKey] ?? String(apiKey)) v\(apiVer)", "kafka.request_key", .int(Int64(apiKey)), o + 4, 4)
        ctx.setInfo("Kafka \(apis[apiKey] ?? "API \(apiKey)") v\(apiVer) request")
        return true
    }
}
