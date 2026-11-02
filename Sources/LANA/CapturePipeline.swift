import Foundation
import PacketCore

/// Capture thread → serial analysis queue → pending buffer drained by the UI at 4 Hz.
/// Keeps the main actor free of per-packet work; thread-safety is by queue + lock.
final class CapturePipeline: @unchecked Sendable {
    struct Item: Sendable {
        let packet: CapturedPacket
        let matches: Bool
        let filterVersion: Int
    }

    let engine = CaptureEngine()
    private var processor = PacketProcessor()          // touched only on `queue`
    private let queue = DispatchQueue(label: "lana.analysis", qos: .userInitiated)
    private let lock = NSLock()
    private var pending: [Item] = []                   // guarded by lock
    private var filter: (DisplayFilter?, Int) = (nil, 0)  // guarded by lock

    init() {
        engine.onBatch = { [unowned self] batch in
            self.queue.async { self.process(batch) }
        }
    }

    func reset(validateChecksums: Bool) {
        queue.sync {
            processor = PacketProcessor()
            processor.validateChecksums = validateChecksums
        }
        lock.withLock { pending.removeAll() }
    }

    @discardableResult
    func setFilter(_ f: DisplayFilter?) -> Int {
        lock.withLock {
            filter = (f, filter.1 + 1)
            return filter.1
        }
    }

    var currentFilter: (DisplayFilter?, Int) { lock.withLock { filter } }

    func takePending() -> [Item] {
        lock.withLock {
            let p = pending
            pending.removeAll(keepingCapacity: true)
            return p
        }
    }

    /// Runs `done` after everything already queued for analysis has been processed.
    func afterInFlight(_ done: @escaping @Sendable () -> Void) { queue.async(execute: done) }

    private func process(_ batch: [RawPacket]) {
        let (f, version) = currentFilter
        var out: [Item] = []
        out.reserveCapacity(batch.count)
        for raw in batch {
            let (pkt, fields) = processor.processWithFields(raw)
            let ok = f.map { $0.matches(DisplayFilter.lookup(summary: pkt.summary, fields: fields)) } ?? true
            out.append(Item(packet: pkt, matches: ok, filterVersion: version))
        }
        lock.withLock { pending.append(contentsOf: out) }
    }

    static func evaluate(_ f: DisplayFilter?, _ p: CapturedPacket, validate: Bool) -> Bool {
        guard let f else { return true }
        let fields = f.needsFields ? Dissector.dissect(p.raw, number: p.summary.number, validateChecksums: validate).fields : nil
        return f.matches(DisplayFilter.lookup(summary: p.summary, fields: fields))
    }
}
