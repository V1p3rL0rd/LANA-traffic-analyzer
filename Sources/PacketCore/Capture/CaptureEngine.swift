import CPcap
import Foundation
#if canImport(os)
import os
#endif

public enum CaptureError: LocalizedError, Equatable {
    case open(String)
    case activate(Int32, String)
    case permissionDenied(String)
    case filter(String)
    case monitorUnsupported(String)
    case alreadyRunning
    case io(String)

    public var errorDescription: String? {
        switch self {
        case .open(let m): return "Не удалось открыть интерфейс: \(m)"
        case .activate(let c, let m): return "pcap_activate (\(c)): \(m)"
        case .permissionDenied(let m):
            return "Нет доступа к /dev/bpf*: \(m). Выполните Scripts/install-chmodbpf.sh и перелогиньтесь."
        case .filter(let m): return "Ошибка BPF-фильтра: \(m)"
        case .monitorUnsupported(let i): return "Интерфейс \(i) не поддерживает режим мониторинга"
        case .alreadyRunning: return "Захват уже запущен"
        case .io(let m): return m
        }
    }
}

public struct CaptureStats: Sendable, Equatable {
    public var received: UInt32 = 0
    public var dropped: UInt32 = 0
    public var interfaceDropped: UInt32 = 0
    public init() {}
}

enum Log {
    #if canImport(os)
    static let capture = Logger(subsystem: "app.lana", category: "capture")
    static func info(_ s: String) { capture.info("\(s, privacy: .public)") }
    static func error(_ s: String) { capture.error("\(s, privacy: .public)") }
    #else
    static func info(_ s: String) { FileHandle.standardError.write(Data("[info] \(s)\n".utf8)) }
    static func error(_ s: String) { FileHandle.standardError.write(Data("[error] \(s)\n".utf8)) }
    #endif
}

/// Live capture via libpcap on a dedicated thread. Packets are delivered in batches
/// (one batch per pcap_dispatch call) to keep cross-thread overhead low.
public final class CaptureEngine: @unchecked Sendable {
    public struct Options: Sendable {
        public var interface: String
        public var filter: String = ""
        public var snaplen: Int32 = 262_144
        public var promiscuous = true
        public var monitorMode = false
        /// Kernel BPF buffer. Too small → drops at high pps; macOS caps it via debug.bpf_maxbufsize.
        public var bufferSize: Int32 = 16 << 20
        public var timeoutMs: Int32 = 100
        public init(interface: String) { self.interface = interface }
    }

    public var onBatch: (([RawPacket]) -> Void)?
    public var onFinish: ((Error?) -> Void)?
    public private(set) var linkType: Int32 = 1

    private let lock = NSLock()
    private var handle: OpaquePointer?
    private var stopRequested = false

    public init() {}

    /// NSLocking.withLock is missing from older swift-corelibs-foundation; keep the core portable.
    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    public var isRunning: Bool { locked { handle != nil } }

    public func start(_ o: Options) throws {
        try locked { if handle != nil { throw CaptureError.alreadyRunning } }

        var errbuf = [CChar](repeating: 0, count: 512)
        guard let h = pcap_create(o.interface, &errbuf) else { throw CaptureError.open(String(cString: errbuf)) }
        pcap_set_snaplen(h, o.snaplen)
        pcap_set_promisc(h, o.promiscuous ? 1 : 0)
        pcap_set_timeout(h, o.timeoutMs)
        pcap_set_buffer_size(h, o.bufferSize)
        pcap_set_immediate_mode(h, 1)
        if o.monitorMode {
            guard pcap_can_set_rfmon(h) == 1 else { pcap_close(h); throw CaptureError.monitorUnsupported(o.interface) }
            pcap_set_rfmon(h, 1)
        }

        let rc = pcap_activate(h)
        if rc < 0 {
            let msg = String(cString: pcap_geterr(h))
            pcap_close(h)
            // PCAP_ERROR_PERM_DENIED = -8
            throw rc == -8 ? CaptureError.permissionDenied(msg) : CaptureError.activate(rc, msg)
        }
        if rc > 0 { Log.info("pcap_activate warning \(rc): \(String(cString: pcap_geterr(h)))") }

        if !o.filter.isEmpty {
            do { try Self.applyFilter(h, o.filter) } catch { pcap_close(h); throw error }
        }

        let lt = pcap_datalink(h)
        locked {
            handle = h
            stopRequested = false
            linkType = lt
        }
        Log.info("capture started on \(o.interface) dlt=\(lt) filter='\(o.filter)'")

        let thread = Thread { [weak self] in self?.loop(h, linkType: lt) }
        thread.name = "lana.capture"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    public func stop() {
        locked {
            stopRequested = true
            if let handle { pcap_breakloop(handle) }
        }
    }

    public func stats() -> CaptureStats? {
        locked {
            guard let handle else { return nil }
            var ps = pcap_stat()
            guard pcap_stats(handle, &ps) == 0 else { return nil }
            var s = CaptureStats()
            s.received = UInt32(ps.ps_recv)
            s.dropped = UInt32(ps.ps_drop)
            s.interfaceDropped = UInt32(ps.ps_ifdrop)
            return s
        }
    }

    private final class LoopContext {
        let linkType: Int32
        var buffer: [RawPacket] = []
        init(_ lt: Int32) { linkType = lt; buffer.reserveCapacity(512) }
    }

    private func loop(_ h: OpaquePointer, linkType: Int32) {
        let ctx = Unmanaged.passRetained(LoopContext(linkType))
        defer { ctx.release() }
        let user = ctx.toOpaque().assumingMemoryBound(to: u_char.self)
        var failure: Error?

        while !locked({ stopRequested }) {
            let n = pcap_dispatch(h, 1024, { user, hdr, bytes in
                guard let user, let hdr, let bytes else { return }
                let c = Unmanaged<LoopContext>.fromOpaque(UnsafeRawPointer(user)).takeUnretainedValue()
                let caplen = Int(hdr.pointee.caplen)
                let ts = Double(hdr.pointee.ts.tv_sec) + Double(hdr.pointee.ts.tv_usec) / 1_000_000
                c.buffer.append(RawPacket(timestamp: ts, originalLength: Int(hdr.pointee.len), linkType: c.linkType,
                                          data: Array(UnsafeBufferPointer(start: bytes, count: caplen))))
            }, user)

            let c = ctx.takeUnretainedValue()
            if !c.buffer.isEmpty {
                onBatch?(c.buffer)
                c.buffer.removeAll(keepingCapacity: true)
            }
            if n == -2 { break }               // PCAP_ERROR_BREAK
            if n < 0 {                          // e.g. interface went down
                failure = CaptureError.io(String(cString: pcap_geterr(h)))
                break
            }
        }

        locked {
            handle = nil
            pcap_close(h)
        }
        if let failure { Log.error("capture failed: \(failure.localizedDescription)") }
        Log.info("capture stopped")
        onFinish?(failure)
    }

    static func applyFilter(_ h: OpaquePointer, _ expr: String) throws {
        var prog = bpf_program()
        guard pcap_compile(h, &prog, expr, 1, 0xFFFF_FFFF) == 0 else {
            throw CaptureError.filter(String(cString: pcap_geterr(h)))
        }
        defer { pcap_freecode(&prog) }
        guard pcap_setfilter(h, &prog) == 0 else { throw CaptureError.filter(String(cString: pcap_geterr(h))) }
    }
}

public enum BPFValidator {
    /// Compiles `expr` against a dead handle of the given link type. Returns nil if valid.
    public static func validate(_ expr: String, linkType: Int32 = 1) -> String? {
        guard !expr.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        guard let h = pcap_open_dead(linkType, 262_144) else { return "pcap_open_dead failed" }
        defer { pcap_close(h) }
        var prog = bpf_program()
        guard pcap_compile(h, &prog, expr, 1, 0xFFFF_FFFF) == 0 else { return String(cString: pcap_geterr(h)) }
        pcap_freecode(&prog)
        return nil
    }

    public static func linkTypeName(_ dlt: Int32) -> String {
        if let p = pcap_datalink_val_to_name(dlt) { return String(cString: p) }
        return "DLT \(dlt)"
    }
}

public enum PcapFile {
    /// Reads pcap and pcapng (libpcap ≥ 1.1 handles both).
    public static func read(_ url: URL, limit: Int = .max) throws -> [RawPacket] {
        var errbuf = [CChar](repeating: 0, count: 512)
        guard let h = pcap_open_offline(url.path, &errbuf) else { throw CaptureError.io(String(cString: errbuf)) }
        defer { pcap_close(h) }
        let lt = pcap_datalink(h)
        var out: [RawPacket] = []
        var hdr: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<u_char>?
        while out.count < limit {
            let rc = pcap_next_ex(h, &hdr, &data)
            if rc == -2 { break }                     // EOF
            if rc == -1 { throw CaptureError.io(String(cString: pcap_geterr(h))) }
            guard rc == 1, let hdr, let data else { continue }
            let ts = Double(hdr.pointee.ts.tv_sec) + Double(hdr.pointee.ts.tv_usec) / 1_000_000
            out.append(RawPacket(timestamp: ts, originalLength: Int(hdr.pointee.len), linkType: lt,
                                 data: Array(UnsafeBufferPointer(start: data, count: Int(hdr.pointee.caplen)))))
        }
        return out
    }

    /// Writes classic pcap. All packets must share one link type (one capture session).
    public static func write(_ packets: [RawPacket], to url: URL) throws {
        let lt = packets.first?.linkType ?? 1
        guard let dead = pcap_open_dead(lt, 262_144) else { throw CaptureError.io("pcap_open_dead failed") }
        defer { pcap_close(dead) }
        guard let dumper = pcap_dump_open(dead, url.path) else { throw CaptureError.io(String(cString: pcap_geterr(dead))) }
        defer { pcap_dump_close(dumper) }
        let sink = UnsafeMutableRawPointer(dumper).assumingMemoryBound(to: u_char.self)
        for p in packets where p.linkType == lt {
            var hdr = pcap_pkthdr()
            let sec = p.timestamp.rounded(.down)
            hdr.ts.tv_sec = .init(sec)
            hdr.ts.tv_usec = .init(((p.timestamp - sec) * 1_000_000).rounded())
            hdr.caplen = bpf_u_int32(p.data.count)
            hdr.len = bpf_u_int32(p.originalLength)
            p.data.withUnsafeBufferPointer { buf in pcap_dump(sink, &hdr, buf.baseAddress) }
        }
        pcap_dump_flush(dumper)
    }
}
