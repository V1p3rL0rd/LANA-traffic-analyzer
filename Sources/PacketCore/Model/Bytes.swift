import Foundation

/// Bounds-checked big/little-endian readers. Every accessor returns nil instead of trapping,
/// so a malformed packet can never crash the app.
public extension Array where Element == UInt8 {
    @inline(__always) func u8(_ i: Int) -> UInt8? {
        i >= 0 && i < count ? self[i] : nil
    }
    @inline(__always) func be16(_ i: Int) -> UInt16? {
        guard i >= 0, i + 2 <= count else { return nil }
        return UInt16(self[i]) << 8 | UInt16(self[i + 1])
    }
    @inline(__always) func be24(_ i: Int) -> UInt32? {
        guard i >= 0, i + 3 <= count else { return nil }
        return UInt32(self[i]) << 16 | UInt32(self[i + 1]) << 8 | UInt32(self[i + 2])
    }
    @inline(__always) func be32(_ i: Int) -> UInt32? {
        guard i >= 0, i + 4 <= count else { return nil }
        return UInt32(self[i]) << 24 | UInt32(self[i + 1]) << 16 | UInt32(self[i + 2]) << 8 | UInt32(self[i + 3])
    }
    @inline(__always) func le16(_ i: Int) -> UInt16? {
        guard i >= 0, i + 2 <= count else { return nil }
        return UInt16(self[i + 1]) << 8 | UInt16(self[i])
    }
    @inline(__always) func le32(_ i: Int) -> UInt32? {
        guard i >= 0, i + 4 <= count else { return nil }
        return UInt32(self[i + 3]) << 24 | UInt32(self[i + 2]) << 16 | UInt32(self[i + 1]) << 8 | UInt32(self[i])
    }
    func sub(_ i: Int, _ len: Int) -> [UInt8]? {
        guard i >= 0, len >= 0, i + len <= count else { return nil }
        return Array(self[i ..< i + len])
    }
    /// Printable ASCII line starting at `i`, up to CRLF/LF or `max` bytes.
    func asciiLine(_ i: Int, max: Int = 256) -> String? {
        guard i < count else { return nil }
        var end = i
        while end < count, end - i < max, self[end] != 0x0A, self[end] != 0x0D { end += 1 }
        let slice = self[i ..< end]
        guard slice.allSatisfy({ ($0 >= 0x20 && $0 < 0x7F) || $0 == 0x09 }) else { return nil }
        return String(decoding: slice, as: UTF8.self)
    }
}

public enum Fmt {
    public static func ipv4(_ v: UInt32) -> String {
        "\(v >> 24).\((v >> 16) & 0xFF).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }

    /// RFC 5952 canonical form (longest zero run compressed).
    public static func ipv6(_ b: [UInt8]) -> String {
        guard b.count == 16 else { return "?" }
        var words = [UInt16](repeating: 0, count: 8)
        for i in 0 ..< 8 { words[i] = UInt16(b[2 * i]) << 8 | UInt16(b[2 * i + 1]) }
        var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
        for i in 0 ..< 8 {
            if words[i] == 0 {
                if curStart < 0 { curStart = i; curLen = 0 }
                curLen += 1
                if curLen > bestLen { bestLen = curLen; bestStart = curStart }
            } else { curStart = -1; curLen = 0 }
        }
        if bestLen < 2 { bestStart = -1 }
        var out = ""
        var i = 0
        while i < 8 {
            if i == bestStart {
                out += i == 0 ? "::" : ":"
                i += bestLen
                continue
            }
            out += String(words[i], radix: 16)
            if i < 7 { out += ":" }
            i += 1
        }
        if out.hasSuffix(":") && !out.hasSuffix("::") { out.removeLast() }
        return out
    }

    public static func mac(_ b: [UInt8]) -> String {
        b.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    public static func hex(_ b: [UInt8], sep: String = "") -> String {
        b.map { String(format: "%02x", $0) }.joined(separator: sep)
    }

    public static func hex16(_ v: UInt16) -> String { String(format: "0x%04x", v) }
    public static func hex8(_ v: UInt8) -> String { String(format: "0x%02x", v) }
    public static func hex32(_ v: UInt32) -> String { String(format: "0x%08x", v) }

    public static func bytes(_ n: Int) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f.string(fromByteCount: Int64(n))
    }
}

/// RFC 1071 one's-complement checksum.
public enum Checksum {
    public static func sum(_ data: [UInt8], _ range: Range<Int>, initial: UInt32 = 0) -> UInt32 {
        var s = initial
        var i = range.lowerBound
        let end = Swift.min(range.upperBound, data.count)
        while i + 1 < end {
            s &+= UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < end { s &+= UInt32(data[i]) << 8 }
        return s
    }

    public static func fold(_ s: UInt32) -> UInt16 {
        var v = s
        while v >> 16 != 0 { v = (v & 0xFFFF) + (v >> 16) }
        return ~UInt16(v & 0xFFFF)
    }
}
