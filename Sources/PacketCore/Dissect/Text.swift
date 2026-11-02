import Foundation

enum HTTP {
    static let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND", "MKCOL"]

    static func looksLikeHTTP(_ d: [UInt8], _ o: Int) -> Bool {
        guard let line = d.asciiLine(o, max: 16) else { return false }
        return line.hasPrefix("HTTP/1.") || methods.contains { line.hasPrefix($0 + " ") }
    }

    static func dissect(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        httpLike(ctx, o, end, abbrev: "http", display: "HTTP", title: "Hypertext Transfer Protocol")
    }

    /// Shared by HTTP, RTSP, SIP and SSDP (same start-line + header grammar).
    @discardableResult
    static func httpLike(_ ctx: DissectionContext, _ o: Int, _ end: Int, abbrev: String, display: String, title: String) -> Bool {
        let d = ctx.data
        guard let first = d.asciiLine(o, max: 2048), !first.isEmpty,
              first.contains("HTTP/") || first.contains("RTSP/") || first.contains("SIP/") else {
            ctx.layer(abbrev, "\(title) (continuation / body)", o, end - o, display: display)
            ctx.info += "  Continuation"
            return true
        }
        let node = ctx.layer(abbrev, title, o, end - o, display: display)
        let parts = first.split(separator: " ", maxSplits: 2).map(String.init)
        var p = o
        var lines: [String] = []
        while p < end, lines.count < 100, let line = d.asciiLine(p, max: 8192) {
            let lineEnd = p + line.utf8.count
            let next = d.u8(lineEnd) == 0x0D ? lineEnd + 2 : lineEnd + 1
            if line.isEmpty { break }
            lines.append(line)
            ctx.add(node, line.count > 200 ? String(line.prefix(200)) + "…" : line, nil, nil, p, next - p)
            p = next
        }

        let isResponse = parts.first.map { $0.hasPrefix("HTTP/") || $0.hasPrefix("RTSP/") || $0.hasPrefix("SIP/") } ?? false
        if isResponse, parts.count >= 2, let code = Int(parts[1]) {
            ctx.index("\(abbrev).response.code", .int(Int64(code)))
            ctx.index("\(abbrev).response", .bool(true))
            switch code {
            case 500...699: ctx.flag(.error, .response, "\(display) server error \(code)", key: "\(abbrev).response.error", on: node)
            case 400...499: ctx.flag(.warning, .response, "\(display) client error \(code)", key: "\(abbrev).response.client_error", on: node)
            default: break
            }
        } else if parts.count >= 2 {
            ctx.index("\(abbrev).request.method", .string(parts[0]))
            ctx.index("\(abbrev).request.uri", .string(parts[1]))
            ctx.index("\(abbrev).request", .bool(true))
        }
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "host": ctx.index("\(abbrev).host", .string(value))
            case "user-agent": ctx.index("\(abbrev).user_agent", .string(value))
            case "content-type": ctx.index("\(abbrev).content_type", .string(value))
            case "server": ctx.index("\(abbrev).server", .string(value))
            case "authorization", "proxy-authorization":
                ctx.index("\(abbrev).authorization", .string(value))
                if value.lowercased().hasPrefix("basic") {
                    ctx.flag(.warning, .security, "Cleartext credentials: HTTP Basic authentication", key: "\(abbrev).auth.basic", on: node)
                }
            case "upgrade": ctx.index("\(abbrev).upgrade", .string(value))
            default: break
            }
        }
        ctx.setInfo(first.count > 160 ? String(first.prefix(160)) + "…" : first)
        return true
    }
}

enum Text {
    /// Generic CRLF line protocol: one tree node per line, `analyze` sees each line.
    private static func lines(_ ctx: DissectionContext, _ abbrev: String, _ display: String, _ title: String,
                              _ o: Int, _ end: Int, analyze: (String, Field) -> Void) -> Bool {
        let d = ctx.data
        guard let first = d.asciiLine(o, max: 4096) else {
            ctx.layer(abbrev, "\(title) (data)", o, end - o, display: display)
            ctx.info += "  \(display) data (\(end - o) bytes)"
            return true
        }
        let node = ctx.layer(abbrev, title, o, end - o, display: display)
        var p = o, n = 0
        while p < end, n < 50, let line = d.asciiLine(p, max: 4096) {
            let lineEnd = p + line.utf8.count
            let next = d.u8(lineEnd) == 0x0D ? lineEnd + 2 : lineEnd + 1
            if !line.isEmpty {
                let f = ctx.add(node, line, "\(abbrev).line", .string(line), p, next - p)
                analyze(line, f)
            }
            p = next; n += 1
        }
        ctx.setInfo(first.count > 160 ? String(first.prefix(160)) + "…" : first)
        return true
    }

    private static func replyCode(_ line: String) -> Int? {
        guard line.count >= 3, let c = Int(line.prefix(3)) else { return nil }
        return c
    }

    private static func classifyReply(_ ctx: DissectionContext, _ abbrev: String, _ display: String, _ line: String, _ f: Field) {
        guard let code = replyCode(line) else { return }
        ctx.index("\(abbrev).response.code", .int(Int64(code)))
        if code >= 500 { ctx.flag(.error, .response, "\(display) permanent error \(code)", key: "\(abbrev).response.error", on: f) }
        else if code >= 400 { ctx.flag(.warning, .response, "\(display) transient error \(code)", key: "\(abbrev).response.warning", on: f) }
    }

    static func ssh(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let d = ctx.data
        if let banner = d.asciiLine(o, max: 255), banner.hasPrefix("SSH-") {
            let node = ctx.layer("ssh", "SSH Protocol", o, end - o, display: "SSH")
            ctx.add(node, "Protocol: \(banner)", "ssh.protocol", .string(banner), o, banner.utf8.count)
            ctx.setInfo("Protocol (\(banner))")
            if banner.hasPrefix("SSH-1.") && !banner.hasPrefix("SSH-1.99") {
                ctx.flag(.warning, .security, "SSH protocol version 1 (insecure)", key: "ssh.v1", on: node)
            }
            return true
        }
        let node = ctx.layer("ssh", "SSH Protocol", o, end - o, display: "SSH")
        if let plen = d.be32(o), let msg = d.u8(o + 5), plen < 35000, msg >= 20, msg <= 34 {
            let names: [UInt8: String] = [20: "Key Exchange Init", 21: "New Keys", 30: "Elliptic Curve DH Key Exchange Init",
                                          31: "Elliptic Curve DH Key Exchange Reply"]
            ctx.add(node, "Message Code: \(names[msg] ?? String(msg))", "ssh.message_code", .int(Int64(msg)), o + 5, 1)
            ctx.setInfo(names[msg] ?? "Key exchange message \(msg)")
        } else {
            ctx.setInfo("Encrypted packet (len=\(end - o))")
        }
        return true
    }

    static func ftp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        lines(ctx, "ftp", "FTP", "File Transfer Protocol", o, end) { line, f in
            let up = line.uppercased()
            if up.hasPrefix("PASS ") {
                ctx.flag(.warning, .security, "Cleartext FTP password", key: "ftp.cleartext_password", on: f)
            } else if up.hasPrefix("USER ") {
                ctx.index("ftp.request.arg", .string(String(line.dropFirst(5))))
            }
            classifyReply(ctx, "ftp", "FTP", line, f)
        }
    }

    static func smtp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        lines(ctx, "smtp", "SMTP", "Simple Mail Transfer Protocol", o, end) { line, f in
            let up = line.uppercased()
            if up.hasPrefix("AUTH PLAIN") || up.hasPrefix("AUTH LOGIN") {
                ctx.flag(.warning, .security, "SMTP AUTH \(up.contains("PLAIN") ? "PLAIN" : "LOGIN") — cleartext unless after STARTTLS",
                         key: "smtp.auth.cleartext", on: f)
            }
            classifyReply(ctx, "smtp", "SMTP", line, f)
        }
    }

    static func pop(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        lines(ctx, "pop", "POP", "Post Office Protocol", o, end) { line, f in
            if line.uppercased().hasPrefix("PASS ") {
                ctx.flag(.warning, .security, "Cleartext POP3 password", key: "pop.cleartext_password", on: f)
            }
            if line.hasPrefix("-ERR") { ctx.flag(.error, .response, "POP3 error: \(line.dropFirst(5))", key: "pop.error", on: f) }
        }
    }

    static func imap(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        lines(ctx, "imap", "IMAP", "Internet Message Access Protocol", o, end) { line, f in
            let tokens = line.split(separator: " ")
            if tokens.count >= 2 {
                let cmd = tokens[1].uppercased()
                if cmd == "LOGIN" { ctx.flag(.warning, .security, "Cleartext IMAP LOGIN", key: "imap.cleartext_login", on: f) }
                if cmd == "NO" { ctx.flag(.warning, .response, "IMAP NO response", key: "imap.no", on: f) }
                if cmd == "BAD" { ctx.flag(.error, .response, "IMAP BAD response", key: "imap.bad", on: f) }
            }
        }
    }

    static func telnet(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        let node = ctx.layer("telnet", "Telnet", o, end - o, display: "TELNET")
        let printable = ctx.data[o ..< end].filter { $0 >= 0x20 && $0 < 0x7F }
        ctx.add(node, "Data: \(String(decoding: printable.prefix(120), as: UTF8.self))", "telnet.data",
                .string(String(decoding: printable, as: UTF8.self)), o, end - o)
        ctx.setInfo("Telnet Data …")
        ctx.flag(.warning, .security, "Telnet: cleartext remote session", key: "telnet.cleartext", on: node)
        return true
    }

    static func sip(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        guard let first = ctx.data.asciiLine(o, max: 512), first.contains("SIP/2.0") else { return false }
        return HTTP.httpLike(ctx, o, end, abbrev: "sip", display: "SIP", title: "Session Initiation Protocol")
    }

    static func rtsp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        HTTP.httpLike(ctx, o, end, abbrev: "rtsp", display: "RTSP", title: "Real Time Streaming Protocol")
    }

    static func ssdp(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        HTTP.httpLike(ctx, o, end, abbrev: "ssdp", display: "SSDP", title: "Simple Service Discovery Protocol")
    }

    static func redis(_ ctx: DissectionContext, _ o: Int, _ end: Int, _ isTCP: Bool) -> Bool {
        guard let c = ctx.data.u8(o), [0x2B, 0x2D, 0x3A, 0x24, 0x2A].contains(c) else { return false } // + - : $ *
        return lines(ctx, "resp", "RESP", "Redis Serialization Protocol", o, end) { line, f in
            if line.hasPrefix("-") { ctx.flag(.warning, .response, "Redis error reply: \(line.dropFirst())", key: "redis.error", on: f) }
            if line.uppercased() == "AUTH" { ctx.flag(.warning, .security, "Redis AUTH in cleartext", key: "redis.auth", on: f) }
        }
    }
}
