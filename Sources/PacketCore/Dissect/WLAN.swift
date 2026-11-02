import Foundation

/// IEEE 802.11 (monitor mode) — radiotap header + MAC header + management SSID / data LLC demux.
enum WLAN {
    static func radiotap(_ ctx: DissectionContext) {
        let d = ctx.data
        guard d.u8(0) == 0, let len = d.le16(2), let present = d.le32(4), Int(len) <= d.count else {
            ctx.malformed("Radiotap", ctx.layer("radiotap", "Radiotap Header", 0, d.count)); return
        }
        let node = ctx.layer("radiotap", "Radiotap Header v0, Length \(len)", 0, Int(len), display: "Radiotap")
        ctx.add(node, "Present flags: \(Fmt.hex32(present))", "radiotap.present", .int(Int64(present)), 4, 4)
        frame(ctx, Int(len))
    }

    static func frame(_ ctx: DissectionContext, _ o: Int) {
        let d = ctx.data
        guard let fc = d.le16(o), let a1 = d.sub(o + 4, 6) else {
            ctx.malformed("802.11", ctx.layer("wlan", "IEEE 802.11", o, d.count - o, display: "802.11")); return
        }
        let type = Int((fc >> 2) & 0x3), sub = Int((fc >> 4) & 0xF)
        let flags = UInt8(fc >> 8)
        let toDS = flags & 0x01 != 0, fromDS = flags & 0x02 != 0, retry = flags & 0x08 != 0, protected = flags & 0x40 != 0
        let mgmt = ["Association Request", "Association Response", "Reassociation Request", "Reassociation Response",
                    "Probe Request", "Probe Response", "Timing Advertisement", "Reserved", "Beacon frame", "ATIM",
                    "Disassociate", "Authentication", "Deauthentication", "Action", "Action No Ack", "Reserved"]
        let ctrl = [8: "Block Ack Request", 9: "Block Ack", 10: "PS-Poll", 11: "Request-to-send", 12: "Clear-to-send",
                    13: "Acknowledgement", 14: "CF-End", 15: "CF-End + CF-Ack"]
        let name: String
        switch type {
        case 0: name = mgmt[sub]
        case 1: name = ctrl[sub] ?? "Control \(sub)"
        case 2: name = sub & 0x8 != 0 ? "QoS Data" : (sub & 0x4 != 0 ? "Null function (No data)" : "Data")
        default: name = "Extension"
        }
        let node = ctx.layer("wlan", "IEEE 802.11 \(name)", o, 24, display: "802.11")
        ctx.add(node, "Type/Subtype: \(name) (\(String(format: "0x%02x", type << 4 | sub)))", "wlan.fc.type_subtype",
                .int(Int64(type << 4 | sub)), o, 2)
        ctx.add(node, "Flags: \(Fmt.hex8(flags))\(retry ? " Retry" : "")\(protected ? " Protected" : "")", "wlan.flags", .int(Int64(flags)), o + 1, 1)
        ctx.index("wlan.fc.retry", .bool(retry)); ctx.index("wlan.fc.protected", .bool(protected))
        ctx.add(node, "Receiver address: \(Fmt.mac(a1))", "wlan.ra", .mac(a1), o + 4, 6)
        ctx.index("wlan.addr", .mac(a1))
        var src = "", dst = Fmt.mac(a1)
        if let a2 = d.sub(o + 10, 6), !(type == 1 && (sub == 12 || sub == 13)) {
            ctx.add(node, "Transmitter address: \(Fmt.mac(a2))", "wlan.ta", .mac(a2), o + 10, 6)
            ctx.index("wlan.addr", .mac(a2))
            src = Fmt.mac(a2)
        }
        if let a3 = d.sub(o + 16, 6), type != 1 {
            ctx.add(node, "BSS Id / Address 3: \(Fmt.mac(a3))", "wlan.bssid", .mac(a3), o + 16, 6)
            if type == 2, toDS, !fromDS { dst = Fmt.mac(a3) }
        }
        ctx.setAddresses(src, dst, network: false)
        ctx.setInfo(name)
        if retry { ctx.flag(.note, .performance, "802.11 retransmission", key: "wlan.fc.retry", on: node) }

        switch type {
        case 0:
            let body = o + 24
            if sub == 12 || sub == 10, let reason = d.le16(body) {
                ctx.setInfo("\(name), Reason code \(reason)")
                ctx.flag(.warning, .security, "\(name) (reason \(reason)) — check for deauth attack", key: "wlan.deauth", on: node)
            }
            if sub == 11, let status = d.le16(body + 4), status != 0 {
                ctx.flag(.error, .response, "802.11 authentication failed (status \(status))", key: "wlan.auth.failed", on: node)
            }
            if sub == 1 || sub == 3, let status = d.le16(body + 2), status != 0 {
                ctx.flag(.error, .response, "Association refused (status \(status))", key: "wlan.assoc.failed", on: node)
            }
            if sub == 8 || sub == 5 || sub == 4 {
                var p = body + (sub == 4 ? 0 : 12)
                while let id = d.u8(p), let l = d.u8(p + 1), p + 2 + Int(l) <= d.count {
                    if id == 0 {
                        let ssid = l == 0 ? "<Wildcard>" : String(decoding: d[(p + 2) ..< (p + 2 + Int(l))], as: UTF8.self)
                        ctx.add(node, "SSID: \(ssid)", "wlan.ssid", .string(ssid), p, 2 + Int(l))
                        ctx.setInfo("\(name), SSID=\(ssid)")
                        break
                    }
                    p += 2 + Int(l)
                }
            }
        case 2:
            guard !protected else { ctx.setInfo("\(name), Protected"); return }
            var hdr = 24 + (toDS && fromDS ? 6 : 0) + (sub & 0x8 != 0 ? 2 : 0)
            if flags & 0x80 != 0 { hdr += 4 }      // +HTC
            let l = o + hdr
            if d.u8(l) == 0xAA, d.u8(l + 1) == 0xAA, let et = d.be16(l + 6) { Dissector.etherType(ctx, et, l + 8) }
        default: break
        }
    }
}
