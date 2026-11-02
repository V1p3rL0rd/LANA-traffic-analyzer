import PacketCore
import SwiftUI

struct PacketDetailView: View {
    @Environment(CaptureSession.self) private var session

    var body: some View {
        Group {
            if session.selectedTree.isEmpty {
                ContentUnavailableView("Пакет не выбран", systemImage: "list.bullet.indent",
                                       description: Text("Выберите пакет в списке, чтобы увидеть дерево протоколов"))
            } else {
                List(session.selectedTree, children: \.children, selection: Bindable(session).treeSelection) { field in
                    FieldRow(field: field)
                }
                .listStyle(.plain)
                .font(.system(size: 12, design: .monospaced))
            }
        }
        .onChange(of: session.treeSelection) { _, id in
            session.highlightedRange = id.flatMap { find($0, in: session.selectedTree) }?.range
        }
        .onChange(of: session.selectedIndex) { _, _ in session.treeSelection = nil }
    }

    private func find(_ id: Field.ID, in nodes: [Field]) -> Field? {
        for n in nodes {
            if n.id == id { return n }
            if let c = n.children, let hit = find(id, in: c) { return hit }
        }
        return nil
    }
}

private struct FieldRow: View {
    let field: Field

    var body: some View {
        HStack(spacing: 4) {
            if let sev = field.severity {
                Image(systemName: sev == .error ? "xmark.octagon.fill" : sev == .warning ? "exclamationmark.triangle.fill" : "info.circle")
                    .foregroundStyle(sev == .error ? Color.red : sev == .warning ? Color.yellow : Color.blue)
                    .imageScale(.small)
            }
            Text(field.label)
                .lineLimit(1)
                .truncationMode(.tail)
                .textSelection(.enabled)
        }
        .padding(.vertical, 1)
        .listRowBackground(background)
        .help(field.label)
    }

    private var background: Color? {
        switch field.severity {
        case .error: Color.red.opacity(0.22)
        case .warning: Color.yellow.opacity(0.25)
        default: nil
        }
    }
}

struct HexDumpView: View {
    @Environment(CaptureSession.self) private var session

    var body: some View {
        Group {
            if let p = session.selectedPacket {
                ScrollView([.vertical, .horizontal]) {
                    Text(Self.render(p.raw.data, highlight: session.highlightedRange))
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(8)
                }
            } else {
                ContentUnavailableView("Нет данных", systemImage: "number")
            }
        }
        .background(Color(nsColor: .textBackgroundColor))
    }

    /// Classic "offset  hex  ascii" layout; the selected field's bytes are highlighted in both columns.
    static func render(_ data: [UInt8], highlight: Range<Int>?) -> AttributedString {
        var out = AttributedString()
        let maxBytes = min(data.count, 16_384)   // AttributedString cost grows linearly; jumbo frames are capped
        var hl = AttributeContainer()
        hl.swiftUI.backgroundColor = Color.accentColor.opacity(0.35)
        var dim = AttributeContainer()
        dim.swiftUI.foregroundColor = Color.secondary

        for lineStart in stride(from: 0, to: maxBytes, by: 16) {
            out += AttributedString(String(format: "%04x  ", lineStart), attributes: dim)
            var ascii = AttributedString()
            for i in lineStart ..< lineStart + 16 {
                if i < maxBytes {
                    let b = data[i]
                    let isHL = highlight?.contains(i) ?? false
                    let hex = AttributedString(String(format: "%02x", b), attributes: isHL ? hl : AttributeContainer())
                    out += hex
                    // Keep the highlight continuous across the separating space.
                    let nextHL = isHL && (highlight?.contains(i + 1) ?? false) && (i + 1) % 16 != 0
                    out += AttributedString(i % 16 == 7 ? "  " : " ", attributes: nextHL ? hl : AttributeContainer())
                    let ch = (b >= 0x20 && b < 0x7F) ? String(Character(UnicodeScalar(b))) : "·"
                    ascii += AttributedString(ch, attributes: isHL ? hl : AttributeContainer())
                } else {
                    out += AttributedString(i % 16 == 7 ? "    " : "   ")
                }
            }
            out += AttributedString(" ")
            out += ascii
            out += AttributedString("\n")
        }
        if data.count > maxBytes { out += AttributedString("… \(data.count - maxBytes) more bytes", attributes: dim) }
        return out
    }
}
