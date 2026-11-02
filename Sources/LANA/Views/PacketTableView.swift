import AppKit
import PacketCore
import SwiftUI

/// NSTableView-backed packet list: handles millions of rows and full-row severity colouring,
/// which SwiftUI `Table` cannot do on macOS 14.
struct PacketTableView: NSViewRepresentable {
    let session: CaptureSession

    enum Column: String, CaseIterable {
        case number = "No.", time = "Time", source = "Source", destination = "Destination",
             proto = "Protocol", length = "Length", info = "Info"
        var width: CGFloat {
            switch self {
            case .number: 70
            case .time: 110
            case .source, .destination: 200
            case .proto: 90
            case .length: 64
            case .info: 700
            }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(session: session) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.usesAlternatingRowBackgroundColors = false
        table.allowsMultipleSelection = false
        table.rowHeight = 18
        table.intercellSpacing = NSSize(width: 6, height: 0)
        table.style = .plain
        table.gridStyleMask = []
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        for c in Column.allCases {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(c.rawValue))
            col.title = c.rawValue
            col.width = c.width
            col.minWidth = 40
            table.addTableColumn(col)
        }
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.menu = context.coordinator.makeMenu()
        context.coordinator.table = table

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        // Reading these registers Observation dependencies.
        let revision = session.revision
        let filterVersion = session.filterVersion
        let autoScroll = session.autoScroll
        let selected = session.selectedIndex
        context.coordinator.sync(revision: revision, filterVersion: filterVersion, autoScroll: autoScroll, selected: selected)
    }

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        let session: CaptureSession
        weak var table: NSTableView?
        private var lastRevision = -1
        private var lastFilterVersion = -1
        private var lastCount = 0
        private var isSyncing = false
        private let font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)

        init(session: CaptureSession) { self.session = session }

        private var lastSelected: Int?

        /// `visible` is ascending, so a packet index maps to a row by binary search.
        private func row(for index: Int) -> Int? {
            let v = session.store.visible
            var lo = 0, hi = v.count - 1
            while lo <= hi {
                let mid = (lo + hi) / 2
                if v[mid] == index { return mid }
                if v[mid] < index { lo = mid + 1 } else { hi = mid - 1 }
            }
            return nil
        }

        func sync(revision: Int, filterVersion: Int, autoScroll: Bool, selected: Int?) {
            guard let table else { return }
            if selected != lastSelected {
                lastSelected = selected
                if let selected, let r = row(for: selected), table.selectedRow != r {
                    isSyncing = true
                    table.selectRowIndexes([r], byExtendingSelection: false)
                    table.scrollRowToVisible(r)
                    isSyncing = false
                }
            }
            guard revision != lastRevision || filterVersion != lastFilterVersion else { return }
            isSyncing = true
            defer { isSyncing = false }
            let count = session.store.visible.count
            if filterVersion == lastFilterVersion, count >= lastCount {
                if count > lastCount { table.noteNumberOfRowsChanged() }
            } else {
                table.reloadData()
                restoreSelection()
            }
            lastRevision = revision
            lastFilterVersion = filterVersion
            lastCount = count
            if autoScroll, session.isCapturing, count > 0, table.selectedRow < 0 { table.scrollRowToVisible(count - 1) }
        }

        private func restoreSelection() {
            guard let table else { return }
            if let sel = session.selectedIndex, let r = row(for: sel) {
                table.selectRowIndexes([r], byExtendingSelection: false)
                table.scrollRowToVisible(r)
            } else {
                table.deselectAll(nil)
            }
        }

        func numberOfRows(in tableView: NSTableView) -> Int { session.store.visible.count }

        private func packet(at row: Int) -> CapturedPacket? {
            let v = session.store.visible
            guard row >= 0, row < v.count, v[row] < session.store.packets.count else { return nil }
            return session.store.packets[v[row]]
        }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard let id = tableColumn?.identifier, let col = Column(rawValue: id.rawValue), let p = packet(at: row) else { return nil }
            let cell: NSTextField
            if let reused = tableView.makeView(withIdentifier: id, owner: self) as? NSTextField {
                cell = reused
            } else {
                cell = NSTextField(labelWithString: "")
                cell.identifier = id
                cell.font = font
                cell.lineBreakMode = .byTruncatingTail
                cell.cell?.usesSingleLineMode = true
            }
            let s = p.summary
            switch col {
            case .number: cell.stringValue = String(s.number); cell.alignment = .right
            case .time: cell.stringValue = String(format: "%.6f", s.timestamp - session.store.firstTimestamp); cell.alignment = .right
            case .source: cell.stringValue = s.source
            case .destination: cell.stringValue = s.destination
            case .proto: cell.stringValue = s.protocolName
            case .length: cell.stringValue = String(s.length); cell.alignment = .right
            case .info: cell.stringValue = s.info
            }
            cell.toolTip = col == .info ? s.expert.filter { $0.severity >= .warning }.map(\.message).joined(separator: "\n") : nil
            return cell
        }

        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
            let rv = (tableView.makeView(withIdentifier: SeverityRowView.id, owner: self) as? SeverityRowView) ?? SeverityRowView()
            rv.identifier = SeverityRowView.id
            rv.severity = packet(at: row)?.summary.severity
            return rv
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table, !isSyncing else { return }
            let row = table.selectedRow
            session.select(row >= 0 && row < session.store.visible.count ? session.store.visible[row] : nil)
        }

        // MARK: Context menu → display filter shortcuts

        func makeMenu() -> NSMenu {
            let m = NSMenu()
            let items: [(String, Selector)] = [
                ("Фильтр: этот источник", #selector(filterSource)),
                ("Фильтр: это назначение", #selector(filterDestination)),
                ("Фильтр: этот протокол", #selector(filterProtocol)),
                ("Следовать за потоком (conversation)", #selector(filterConversation)),
                ("Исключить этот протокол", #selector(excludeProtocol)),
            ]
            for (title, sel) in items {
                let it = NSMenuItem(title: title, action: sel, keyEquivalent: "")
                it.target = self
                m.addItem(it)
            }
            return m
        }

        private var clicked: CapturedPacket? {
            guard let table else { return nil }
            return packet(at: table.clickedRow >= 0 ? table.clickedRow : table.selectedRow)
        }

        private func addrFilter(_ addr: String, dir: String) -> String {
            if addr.contains(".") , !addr.contains(":") { return "ip.\(dir) == \(addr)" }
            if addr.count == 17, addr.filter({ $0 == ":" }).count == 5 { return "eth.\(dir) == \(addr)" }
            return "ipv6.\(dir) == \(addr)"
        }

        @objc private func filterSource() { if let p = clicked { session.applyDisplayFilter(addrFilter(p.summary.source, dir: "src")) } }
        @objc private func filterDestination() { if let p = clicked { session.applyDisplayFilter(addrFilter(p.summary.destination, dir: "dst")) } }
        @objc private func filterProtocol() {
            if let p = clicked, let proto = p.summary.protocols.last { session.applyDisplayFilter(proto) }
        }
        @objc private func excludeProtocol() {
            if let p = clicked, let proto = p.summary.protocols.last { session.applyDisplayFilter("!\(proto)") }
        }
        @objc private func filterConversation() {
            if let p = clicked, let f = session.conversationFilter(for: p) { session.applyDisplayFilter(f) }
        }
    }
}

/// Full-row background: red = error, yellow = needs attention. Selection highlight still wins.
final class SeverityRowView: NSTableRowView {
    static let id = NSUserInterfaceItemIdentifier("SeverityRow")
    var severity: Severity? { didSet { if oldValue != severity { needsDisplay = true } } }

    override func drawBackground(in dirtyRect: NSRect) {
        super.drawBackground(in: dirtyRect)
        let color: NSColor?
        switch severity {
        case .error: color = NSColor.systemRed.withAlphaComponent(0.38)
        case .warning: color = NSColor.systemYellow.withAlphaComponent(0.40)
        default: color = nil
        }
        if let color {
            color.setFill()
            bounds.fill()
        }
    }
}
