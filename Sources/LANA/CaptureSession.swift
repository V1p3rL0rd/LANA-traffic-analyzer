import AppKit
import Observation
import PacketCore
import os

struct ExpertAggregate: Identifiable {
    let id: String
    let severity: Severity
    let group: ExpertGroup
    let message: String
    let key: String?
    var count: Int
    var packets: [Int]          // indices into PacketStore.packets (first 500)
}

/// Packet storage. Mutated on the main actor only.
final class PacketStore {
    var packets: [CapturedPacket] = []
    /// Indices into `packets` that pass the display filter.
    var visible: [Int] = []
    var firstTimestamp: Double { packets.first?.raw.timestamp ?? 0 }
}

@MainActor
@Observable
final class CaptureSession {
    // MARK: Observable UI state
    var interfaces: [NetworkInterface] = []
    var selectedInterface = ""
    var filterSpec = CaptureFilterSpec() { didSet { recomputeBPF() } }
    private(set) var bpfPreview = ""
    private(set) var bpfError: String?
    var promiscuous = true
    var monitorMode = false
    var validateChecksums = false
    var maxPackets = 2_000_000

    private(set) var isCapturing = false
    private(set) var isBusy = false
    var displayFilterText = ""
    private(set) var displayFilterError: String?
    private(set) var activeDisplayFilter: String?
    var lastError: String?
    private(set) var stats = CaptureStats()
    private(set) var revision = 0
    private(set) var filterVersion = 0
    private(set) var errorCount = 0
    private(set) var warningCount = 0
    private(set) var expertAggregates: [String: ExpertAggregate] = [:]
    private(set) var linkTypeName = ""
    var autoScroll = true
    var showExpert = false
    var showCaptureOptions = false

    private(set) var selectedIndex: Int?
    private(set) var selectedTree: [Field] = []
    var highlightedRange: Range<Int>?

    // View-local UI state lives here: with Command Line Tools only (no Xcode) the SwiftUI
    // `@State` macro plugin is unavailable, so views must not declare @State.
    var treeSelection: ObjectIdentifier?
    var protocolQuery = ""
    var expertShowWarnings = true

    static let shared = CaptureSession()

    // MARK: Internals
    let store = PacketStore()
    private let pipeline = CapturePipeline()
    private var engine: CaptureEngine { pipeline.engine }
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var filterTask: Task<Void, Never>?
    private let log = Logger(subsystem: "app.lana", category: "session")

    init() {
        refreshInterfaces()
        recomputeBPF()
        pipeline.engine.onFinish = { [weak self] error in
            Task { @MainActor in self?.captureFinished(error) }
        }
    }

    var selectedPacket: CapturedPacket? { selectedIndex.map { store.packets[$0] } }

    // MARK: Interfaces & filter

    func refreshInterfaces() {
        do {
            interfaces = try InterfaceDiscovery.list()
            if selectedInterface.isEmpty || !interfaces.contains(where: { $0.name == selectedInterface }) {
                // Prefer the real uplink: Wi-Fi/Ethernet that is up and holds an IPv4 address.
                let physical = interfaces.filter { $0.kind == .wifi || $0.kind == .ethernet }
                selectedInterface = physical.first(where: { $0.isRunning && $0.addresses.contains { !$0.contains(":") } })?.name
                    ?? physical.first(where: { $0.isRunning })?.name
                    ?? interfaces.first?.name ?? ""
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func recomputeBPF() {
        do {
            bpfPreview = try CaptureFilterBuilder.build(filterSpec)
            bpfError = BPFValidator.validate(bpfPreview, linkType: 1)
            // Non-Ethernet links (utun, lo0) reject "ether ..." primitives — validate against DLT_RAW too.
            if bpfError == nil, bpfPreview.contains("ether"),
               let kind = interfaces.first(where: { $0.name == selectedInterface })?.kind, kind == .tunnel || kind == .loopback {
                bpfError = "Выражения «ether …» не поддерживаются на интерфейсе типа \(kind.rawValue)"
            }
        } catch {
            bpfError = error.localizedDescription
        }
    }

    // MARK: Capture control

    func start() {
        guard !isCapturing, !selectedInterface.isEmpty else { return }
        recomputeBPF()
        if let bpfError { lastError = bpfError; return }
        clear()
        var o = CaptureEngine.Options(interface: selectedInterface)
        o.filter = bpfPreview
        o.promiscuous = promiscuous
        o.monitorMode = monitorMode
        pipeline.reset(validateChecksums: validateChecksums)
        do {
            try engine.start(o)
            linkTypeName = BPFValidator.linkTypeName(engine.linkType)
            isCapturing = true
            startTimer()
        } catch {
            lastError = error.localizedDescription
            log.error("start failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func stop() { engine.stop() }

    func toggleCapture() { isCapturing ? stop() : start() }

    private func captureFinished(_ error: Error?) {
        isCapturing = false
        if let error { lastError = error.localizedDescription }
        // Let the analysis queue finish what is in flight, then drain once more.
        pipeline.afterInFlight { [weak self] in
            Task { @MainActor in
                self?.drain()
                self?.timer?.invalidate()
                self?.timer = nil
            }
        }
    }

    func clear() {
        guard !isCapturing else { return }
        filterTask?.cancel()
        store.packets.removeAll(keepingCapacity: true)
        store.visible.removeAll(keepingCapacity: true)
        pipeline.reset(validateChecksums: validateChecksums)
        errorCount = 0; warningCount = 0
        expertAggregates.removeAll()
        stats = CaptureStats()
        select(nil)
        revision += 1
        filterVersion += 1
    }

    private func startTimer() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.drain()
                if let s = self.engine.stats() { self.stats = s }
            }
        }
    }

    private func drain() {
        let items = pipeline.takePending()
        guard !items.isEmpty else { return }
        let current = pipeline.currentFilter
        for item in items {
            let pkt = item.packet
            if store.packets.count >= maxPackets {
                if isCapturing {
                    stop()
                    lastError = "Достигнут лимит \(maxPackets) пакетов в памяти — захват остановлен. Сохраните файл и начните заново."
                }
                break
            }
            store.packets.append(pkt)
            var ok = item.matches
            if item.filterVersion != current.1 { ok = CapturePipeline.evaluate(current.0, pkt, validate: validateChecksums) }
            if ok { store.visible.append(store.packets.count - 1) }
            aggregate(pkt, index: store.packets.count - 1)
            switch pkt.summary.severity {
            case .error: errorCount += 1
            case .warning: warningCount += 1
            default: break
            }
        }
        revision += 1
    }

    private func aggregate(_ pkt: CapturedPacket, index: Int) {
        for e in pkt.summary.expert where e.severity >= .warning {
            let id = "\(e.severity.rawValue)|\(e.key ?? e.message)"
            if expertAggregates[id] == nil {
                expertAggregates[id] = ExpertAggregate(id: id, severity: e.severity, group: e.group, message: e.message,
                                                       key: e.key, count: 0, packets: [])
            }
            expertAggregates[id]!.count += 1
            if expertAggregates[id]!.packets.count < 500 { expertAggregates[id]!.packets.append(index) }
        }
    }

    /// Selects a packet by store index, clearing the display filter if it hides that packet.
    func reveal(_ index: Int) {
        if !store.visible.contains(index) { applyDisplayFilter("") }
        select(index)
        revision += 1
    }

    // MARK: Display filter

    func applyDisplayFilter(_ text: String? = nil) {
        if let text { displayFilterText = text }
        let trimmed = displayFilterText.trimmingCharacters(in: .whitespaces)
        let filter: DisplayFilter?
        if trimmed.isEmpty {
            filter = nil
        } else {
            do { filter = try DisplayFilter(trimmed) } catch {
                displayFilterError = error.localizedDescription
                return
            }
        }
        displayFilterError = nil
        activeDisplayFilter = filter?.source
        filterTask?.cancel()

        pipeline.setFilter(filter)
        let snapshot = store.packets
        let validate = validateChecksums
        isBusy = true
        filterTask = Task.detached(priority: .userInitiated) { [weak self] in
            var visible: [Int] = []
            visible.reserveCapacity(snapshot.count)
            for (i, p) in snapshot.enumerated() {
                if i % 4096 == 0, Task.isCancelled { return }
                if CapturePipeline.evaluate(filter, p, validate: validate) { visible.append(i) }
            }
            await MainActor.run {
                guard let self, !Task.isCancelled else { return }
                // Packets appended while filtering were evaluated in drain() against the new version.
                let tail = self.store.visible.filter { $0 >= snapshot.count }
                self.store.visible = visible + tail
                self.filterVersion += 1
                self.revision += 1
                self.isBusy = false
            }
        }
    }

    func filterOn(_ expression: String) { applyDisplayFilter(expression) }

    // MARK: Selection

    func select(_ index: Int?) {
        selectedIndex = index
        highlightedRange = nil
        guard let index, index < store.packets.count else { selectedTree = []; return }
        let p = store.packets[index]
        let ctx = Dissector.dissect(p.raw, number: p.summary.number, validateChecksums: validateChecksums)
        ctx.merge(p.summary.expert)
        ctx.appendExpertTree()
        selectedTree = ctx.tree
    }

    func conversationFilter(for p: CapturedPacket) -> String? {
        let ctx = Dissector.dissect(p.raw, number: p.summary.number)
        if let t = ctx.tcp {
            let a = ctx.fields["ip.src"] != nil ? "ip" : "ipv6"
            return "\(a).addr == \(t.srcAddr) && \(a).addr == \(t.dstAddr) && tcp.port == \(t.srcPort) && tcp.port == \(t.dstPort)"
        }
        if let s = ctx.netSource, let d = ctx.netDestination {
            let a = ctx.fields["ip.src"] != nil ? "ip" : "ipv6"
            if let sp = ctx.fields["udp.srcport"]?.first, let dp = ctx.fields["udp.dstport"]?.first {
                return "\(a).addr == \(s) && \(a).addr == \(d) && udp.port == \(sp.displayString) && udp.port == \(dp.displayString)"
            }
            return "\(a).addr == \(s) && \(a).addr == \(d)"
        }
        return nil
    }

    // MARK: Files

    func open(_ url: URL) {
        guard !isCapturing else { return }
        clear()
        isBusy = true
        let validate = validateChecksums
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let raws = try PcapFile.read(url)
                let proc = PacketProcessor()
                proc.validateChecksums = validate
                let packets = raws.map { proc.process($0) }
                await MainActor.run {
                    guard let self else { return }
                    self.store.packets = packets
                    self.errorCount = packets.filter { $0.summary.severity == .error }.count
                    self.warningCount = packets.filter { $0.summary.severity == .warning }.count
                    for (i, p) in packets.enumerated() { self.aggregate(p, index: i) }
                    self.linkTypeName = raws.first.map { BPFValidator.linkTypeName($0.linkType) } ?? ""
                    self.stats.received = UInt32(clamping: packets.count)
                    self.isBusy = false
                    self.applyDisplayFilter()
                }
            } catch {
                await MainActor.run {
                    self?.lastError = error.localizedDescription
                    self?.isBusy = false
                }
            }
        }
    }

    func save(to url: URL, displayedOnly: Bool) {
        let raws = displayedOnly ? store.visible.map { store.packets[$0].raw } : store.packets.map(\.raw)
        do { try PcapFile.write(raws, to: url) } catch { lastError = error.localizedDescription }
    }
}
