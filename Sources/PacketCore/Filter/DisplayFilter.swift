import Foundation

/// Wireshark-compatible subset of the display filter language:
///   ip.addr == 10.0.0.0/8 && tcp.port in {80 443}   (sets: `in {a b c}`)
///   dns.qry.name contains "apple" || !arp
///   http.response.code >= 400, tcp.analysis.retransmission, expert.error
/// Operators: == != > < >= <= eq ne gt lt ge le contains matches ~ in, && || ! and or not, ( ).
public struct DisplayFilter: Sendable {
    public indirect enum Expr: Sendable {
        case and(Expr, Expr)
        case or(Expr, Expr)
        case not(Expr)
        case exists(String)
        case compare(String, Op, String)
        case member(String, [String])
    }

    public enum Op: String, Sendable { case eq, ne, gt, lt, ge, le, contains, matches }

    public struct ParseError: LocalizedError, Sendable {
        public let message: String
        public var errorDescription: String? { message }
    }

    public let source: String
    public let expr: Expr
    /// False when only protocol presence / expert info is referenced → no re-dissection needed.
    public let needsFields: Bool

    public init(_ text: String) throws {
        source = text
        var p = Parser(tokens: try Self.tokenize(text))
        let e = try p.parseOr()
        guard p.atEnd else { throw ParseError(message: "Неожиданный токен «\(p.peek()?.text ?? "")»") }
        expr = e
        needsFields = Self.needsFields(e)
    }

    // MARK: Evaluation

    public func matches(_ lookup: (String) -> [FieldValue]) -> Bool { eval(expr, lookup) }

    /// Field lookup for a packet: fresh dissection fields + stored expert/analysis results.
    public static func lookup(summary: PacketSummary, fields: [String: [FieldValue]]?) -> (String) -> [FieldValue] {
        { name in
            switch name {
            case "expert": return summary.expert.isEmpty ? [] : [.bool(true)]
            case "expert.error": return summary.expert.contains { $0.severity == .error } ? [.bool(true)] : []
            case "expert.warning": return summary.expert.contains { $0.severity == .warning } ? [.bool(true)] : []
            case "expert.severity", "_ws.expert.severity": return summary.expert.map { .string($0.severity.description) }
            case "expert.message", "_ws.expert.message": return summary.expert.map { .string($0.message) }
            case "expert.group", "_ws.expert.group": return summary.expert.map { .string($0.group.rawValue.lowercased()) }
            case "frame.protocols": return [.string(summary.protocols.joined(separator: ":"))]
            default: break
            }
            if summary.expert.contains(where: { $0.key == name }) { return [.bool(true)] }
            if let fields { return fields[name] ?? [] }
            return summary.protocols.contains(name) ? [.bool(true)] : []
        }
    }

    private func eval(_ e: Expr, _ f: (String) -> [FieldValue]) -> Bool {
        switch e {
        case .and(let a, let b): return eval(a, f) && eval(b, f)
        case .or(let a, let b): return eval(a, f) || eval(b, f)
        case .not(let a): return !eval(a, f)
        case .exists(let name): return !f(name).isEmpty
        case .member(let name, let set):
            let values = f(name)
            return values.contains { v in set.contains { Self.equal(v, $0) } }
        case .compare(let name, let op, let lit):
            let values = f(name)
            guard !values.isEmpty else { return false }
            switch op {
            case .eq: return values.contains { Self.equal($0, lit) }
            case .ne: return values.allSatisfy { !Self.equal($0, lit) }      // like Wireshark's "!=" (all_ne)
            case .contains: return values.contains { $0.displayString.localizedCaseInsensitiveContains(lit) }
            case .matches:
                guard let re = try? NSRegularExpression(pattern: lit, options: [.caseInsensitive]) else { return false }
                return values.contains {
                    let s = $0.displayString
                    return re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
                }
            case .gt, .lt, .ge, .le:
                return values.contains { Self.order($0, lit, op) }
            }
        }
    }

    static func intLiteral(_ s: String) -> Int64? {
        let l = s.lowercased()
        if l == "true" { return 1 }
        if l == "false" { return 0 }
        if l.hasPrefix("0x") { return Int64(l.dropFirst(2), radix: 16) }
        return Int64(l)
    }

    static func equal(_ v: FieldValue, _ lit: String) -> Bool {
        switch v {
        case .int(let i): return intLiteral(lit) == i
        case .bool(let b): return intLiteral(lit) == (b ? 1 : 0)
        case .string(let s): return s == lit || s.caseInsensitiveCompare(lit) == .orderedSame
        case .ipv4(let a): return ipv4Match(a, lit)
        case .ipv6(let b): return ipv6Match(b, lit)
        case .mac(let m): return Fmt.mac(m) == lit.lowercased().replacingOccurrences(of: "-", with: ":")
        case .bytes(let b): return Fmt.hex(b) == lit.lowercased().replacingOccurrences(of: ":", with: "")
        }
    }

    static func order(_ v: FieldValue, _ lit: String, _ op: Op) -> Bool {
        let cmp: Int
        switch v {
        case .int(let i):
            guard let l = intLiteral(lit) else { return false }
            cmp = i < l ? -1 : (i > l ? 1 : 0)
        case .string(let s):
            cmp = s < lit ? -1 : (s > lit ? 1 : 0)
        case .ipv4(let a):
            guard let l = parseIPv4(lit) else { return false }
            cmp = a < l ? -1 : (a > l ? 1 : 0)
        default: return false
        }
        switch op {
        case .gt: return cmp > 0
        case .lt: return cmp < 0
        case .ge: return cmp >= 0
        case .le: return cmp <= 0
        default: return false
        }
    }

    static func parseIPv4(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let o = UInt8(p) else { return nil }
            v = v << 8 | UInt32(o)
        }
        return v
    }

    static func ipv4Match(_ a: UInt32, _ lit: String) -> Bool {
        let parts = lit.split(separator: "/", maxSplits: 1)
        guard let base = parseIPv4(String(parts[0])) else { return false }
        guard parts.count == 2, let len = Int(parts[1]), (0 ... 32).contains(len) else { return a == base }
        let mask: UInt32 = len == 0 ? 0 : ~UInt32(0) << UInt32(32 - len)
        return a & mask == base & mask
    }

    static func ipv6Match(_ b: [UInt8], _ lit: String) -> Bool {
        let parts = lit.split(separator: "/", maxSplits: 1)
        var addr = in6_addr()
        guard String(parts[0]).withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return false }
        let base = withUnsafeBytes(of: &addr) { Array($0) }
        let len = parts.count == 2 ? (Int(parts[1]) ?? 128) : 128
        guard (0 ... 128).contains(len) else { return false }
        for i in 0 ..< 16 {
            let bits = max(0, min(8, len - i * 8))
            if bits == 0 { break }
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
            if b[i] & mask != base[i] & mask { return false }
        }
        return true
    }

    private static func needsFields(_ e: Expr) -> Bool {
        switch e {
        case .and(let a, let b), .or(let a, let b): return needsFields(a) || needsFields(b)
        case .not(let a): return needsFields(a)
        case .exists(let n): return n.contains(".") && !n.hasPrefix("expert") && !n.hasPrefix("tcp.analysis") && !n.hasPrefix("_ns.")
        case .compare(let n, _, _), .member(let n, _): return !n.hasPrefix("expert") && !n.hasPrefix("_ws.expert")
        }
    }

    // MARK: Lexer / parser

    struct Token { enum Kind { case word, string, op, lparen, rparen, lbrace, rbrace }; let kind: Kind; let text: String }

    static func tokenize(_ s: String) throws -> [Token] {
        var out: [Token] = []
        let chars = Array(s)
        var i = 0
        let opChars: Set<Character> = ["=", "!", "<", ">", "&", "|", "~"]
        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { i += 1; continue }
            if c == "(" { out.append(Token(kind: .lparen, text: "(")); i += 1; continue }
            if c == ")" { out.append(Token(kind: .rparen, text: ")")); i += 1; continue }
            if c == "{" { out.append(Token(kind: .lbrace, text: "{")); i += 1; continue }
            if c == "}" { out.append(Token(kind: .rbrace, text: "}")); i += 1; continue }
            if c == "\"" {
                var j = i + 1, str = ""
                while j < chars.count, chars[j] != "\"" {
                    if chars[j] == "\\", j + 1 < chars.count { j += 1 }
                    str.append(chars[j]); j += 1
                }
                guard j < chars.count else { throw ParseError(message: "Незакрытая кавычка") }
                out.append(Token(kind: .string, text: str)); i = j + 1; continue
            }
            if opChars.contains(c) {
                var j = i
                while j < chars.count, opChars.contains(chars[j]), j - i < 2 { j += 1 }
                var op = String(chars[i ..< j])
                // "!" followed by another operator char that is not "=" → unary not
                if op.count == 2, op.first == "!", op != "!=" { op = "!"; j = i + 1 }
                if op.count == 2, ["==", "!=", ">=", "<=", "&&", "||"].contains(op) == false { op = String(op.first!); j = i + 1 }
                out.append(Token(kind: .op, text: op)); i = j; continue
            }
            var j = i
            while j < chars.count, !chars[j].isWhitespace, !"(){}\"=!<>&|~,".contains(chars[j]) { j += 1 }
            out.append(Token(kind: .word, text: String(chars[i ..< j])))
            i = j
            if i < chars.count, chars[i] == "," { i += 1 }   // allow commas inside sets
        }
        return out
    }

    struct Parser {
        let tokens: [Token]
        var pos = 0
        var atEnd: Bool { pos >= tokens.count }
        func peek() -> Token? { pos < tokens.count ? tokens[pos] : nil }
        mutating func next() -> Token? { defer { pos += 1 }; return peek() }

        func isKeyword(_ t: Token?, _ words: Set<String>) -> Bool {
            guard let t else { return false }
            return words.contains(t.text.lowercased()) && (t.kind == .op || t.kind == .word)
        }

        mutating func parseOr() throws -> Expr {
            var lhs = try parseAnd()
            while isKeyword(peek(), ["||", "or"]) { pos += 1; lhs = .or(lhs, try parseAnd()) }
            return lhs
        }

        mutating func parseAnd() throws -> Expr {
            var lhs = try parseNot()
            while isKeyword(peek(), ["&&", "and"]) { pos += 1; lhs = .and(lhs, try parseNot()) }
            return lhs
        }

        mutating func parseNot() throws -> Expr {
            if isKeyword(peek(), ["!", "not"]) { pos += 1; return .not(try parseNot()) }
            return try parsePrimary()
        }

        mutating func parsePrimary() throws -> Expr {
            guard let t = next() else { throw ParseError(message: "Неожиданный конец выражения") }
            if t.kind == .lparen {
                let e = try parseOr()
                guard next()?.kind == .rparen else { throw ParseError(message: "Ожидалась «)»") }
                return e
            }
            guard t.kind == .word, t.text.first.map({ $0.isLetter || $0 == "_" }) == true else {
                throw ParseError(message: "Ожидалось имя поля или протокола, получено «\(t.text)»")
            }
            let field = t.text.lowercased()
            let ops: [String: Op] = ["==": .eq, "eq": .eq, "!=": .ne, "ne": .ne, ">": .gt, "gt": .gt, "<": .lt, "lt": .lt,
                                     ">=": .ge, "ge": .ge, "<=": .le, "le": .le, "contains": .contains, "matches": .matches, "~": .matches]
            guard let opTok = peek(), let op = ops[opTok.text.lowercased()] else {
                if peek()?.text.lowercased() == "in" {
                    pos += 1
                    guard next()?.kind == .lbrace else { throw ParseError(message: "Ожидалась «{» после in") }
                    var items: [String] = []
                    while let it = peek(), it.kind != .rbrace { items.append(it.text); pos += 1 }
                    guard next()?.kind == .rbrace else { throw ParseError(message: "Ожидалась «}»") }
                    return .member(field, items)
                }
                return .exists(field)
            }
            pos += 1
            guard let v = next(), v.kind == .word || v.kind == .string else {
                throw ParseError(message: "Ожидалось значение после «\(opTok.text)»")
            }
            return .compare(field, op, v.text)
        }
    }
}
