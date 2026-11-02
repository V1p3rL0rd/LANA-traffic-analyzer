import PacketCore
import SwiftUI

/// Aggregated anomalies for the whole capture, Wireshark "Expert Information" style.
struct ExpertInfoView: View {
    @Environment(CaptureSession.self) private var session

    private var items: [ExpertAggregate] {
        session.expertAggregates.values
            .filter { session.expertShowWarnings || $0.severity == .error }
            .sorted { ($0.severity.rawValue, $0.count) > ($1.severity.rawValue, $1.count) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Аномалии").font(.headline)
                Spacer()
                Toggle("Предупреждения", isOn: Bindable(session).expertShowWarnings).toggleStyle(.checkbox).font(.caption)
            }
            .padding(10)
            Divider()
            if items.isEmpty {
                ContentUnavailableView("Аномалий нет", systemImage: "checkmark.shield",
                                       description: Text("Ошибки и предупреждения появятся здесь во время захвата"))
            } else {
                List(items) { item in
                    DisclosureGroup {
                        ForEach(item.packets.prefix(100), id: \.self) { idx in
                            Button {
                                session.reveal(idx)
                            } label: {
                                Text("Пакет #\(session.store.packets[idx].summary.number)  \(session.store.packets[idx].summary.info)")
                                    .lineLimit(1)
                                    .font(.system(size: 11, design: .monospaced))
                            }
                            .buttonStyle(.plain)
                        }
                        if item.count > 100 { Text("… ещё \(item.count - 100)").foregroundStyle(.secondary).font(.caption) }
                    } label: {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: item.severity == .error ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(item.severity == .error ? Color.red : Color.yellow)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.message).lineLimit(2)
                                Text("\(item.group.rawValue)\(item.key.map { " · \($0)" } ?? "")")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("\(item.count)").monospacedDigit().foregroundStyle(.secondary)
                        }
                        .contextMenu {
                            if let key = item.key {
                                Button("Применить как фильтр: \(key)") { session.applyDisplayFilter(key) }
                            }
                        }
                        .onTapGesture(count: 2) {
                            if let key = item.key { session.applyDisplayFilter(key) }
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
    }
}
