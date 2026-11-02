import PacketCore
import SwiftUI

struct ContentView: View {
    @Environment(CaptureSession.self) private var session

    var body: some View {
        @Bindable var session = session
        VStack(spacing: 0) {
            DisplayFilterBar()
            Divider()
            VSplitView {
                PacketTableView(session: session)
                    .frame(minHeight: 180, idealHeight: 380)
                HSplitView {
                    PacketDetailView()
                        .frame(minWidth: 320, idealWidth: 520)
                    HexDumpView()
                        .frame(minWidth: 300, idealWidth: 460)
                }
                .frame(minHeight: 160, idealHeight: 260)
            }
            Divider()
            StatusBarView()
        }
        .toolbar { toolbar }
        .inspector(isPresented: $session.showExpert) {
            ExpertInfoView()
                .inspectorColumnWidth(min: 280, ideal: 340, max: 520)
        }
        .sheet(isPresented: $session.showCaptureOptions) {
            CaptureOptionsView()
        }
        .alert("LANA", isPresented: Binding(get: { session.lastError != nil }, set: { if !$0 { session.lastError = nil } })) {
            Button("OK") { session.lastError = nil }
        } message: {
            Text(session.lastError ?? "")
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Picker("Интерфейс", selection: Bindable(session).selectedInterface) {
                ForEach(session.interfaces) { iface in
                    Label(iface.displayName + (iface.isRunning ? "" : " · неактивен"), systemImage: iface.kind.symbol)
                        .tag(iface.name)
                }
            }
            .frame(width: 300)
            .disabled(session.isCapturing)
            .help("Сетевой интерфейс для захвата")
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button {
                session.toggleCapture()
            } label: {
                Label(session.isCapturing ? "Стоп" : "Старт",
                      systemImage: session.isCapturing ? "stop.fill" : "play.fill")
            }
            .tint(session.isCapturing ? .red : .accentColor)
            .help(session.isCapturing ? "Остановить захват (⌘E)" : "Начать захват (⌘E)")

            Button { session.showCaptureOptions = true } label: {
                Label("Фильтр захвата", systemImage: session.filterSpec.isEmpty ? "line.3.horizontal.decrease.circle"
                                                                              : "line.3.horizontal.decrease.circle.fill")
            }
            .help("srcaddr / dstaddr / протоколы (⌘K)")
            .disabled(session.isCapturing)

            Button { session.clear() } label: { Label("Очистить", systemImage: "trash") }
                .disabled(session.isCapturing)

            Button { FileActions.open(session) } label: { Label("Открыть", systemImage: "folder") }
                .disabled(session.isCapturing)
            Button { FileActions.save(session, displayedOnly: false) } label: { Label("Сохранить", systemImage: "square.and.arrow.down") }
                .disabled(session.store.packets.isEmpty && session.revision >= 0)

            Toggle(isOn: Bindable(session).autoScroll) { Label("Автопрокрутка", systemImage: "arrow.down.to.line") }
                .help("Прокручивать к новым пакетам")
            Button { session.showExpert.toggle() } label: { Label("Аномалии", systemImage: "exclamationmark.triangle") }
                .help("Панель аномалий (⌥⌘I)")
        }
    }
}

struct DisplayFilterBar: View {
    @Environment(CaptureSession.self) private var session
    @FocusState private var focused: Bool

    private struct Preset: Hashable { let name: String; let filter: String }

    private let presets: [Preset] = [
        Preset(name: "Ошибки", filter: "expert.error"),
        Preset(name: "Ошибки + предупреждения", filter: "expert.error || expert.warning"),
        Preset(name: "TCP проблемы", filter: "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.zero_window || tcp.analysis.lost_segment"),
        Preset(name: "TCP RST", filter: "tcp.flags.reset == 1"),
        Preset(name: "DNS ошибки", filter: "dns.flags.rcode > 0"),
        Preset(name: "HTTP 4xx/5xx", filter: "http.response.code >= 400"),
        Preset(name: "TLS ClientHello", filter: "tls.handshake.type == 1"),
        Preset(name: "Безопасность", filter: "expert.group == security"),
        Preset(name: "ARP", filter: "arp"),
        Preset(name: "Не TCP/UDP", filter: "!tcp && !udp"),
    ]

    var body: some View {
        @Bindable var session = session
        HStack(spacing: 6) {
            Image(systemName: "line.3.horizontal.decrease")
                .foregroundStyle(.secondary)
            TextField("Display filter: ip.addr == 10.0.0.0/8 && tcp.port in {80 443} · dns · expert.error",
                      text: $session.displayFilterText)
                .textFieldStyle(.plain)
                .font(.system(.body, design: .monospaced))
                .focused($focused)
                .onSubmit { session.applyDisplayFilter() }
            if session.isBusy { ProgressView().controlSize(.small) }
            Menu {
                ForEach(presets, id: \.self) { p in
                    Button(p.name) { session.applyDisplayFilter(p.filter) }
                }
            } label: { Image(systemName: "bookmark") }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Готовые фильтры")
            Button("Применить") { session.applyDisplayFilter() }
                .keyboardShortcut(.return, modifiers: [.command])
            if session.activeDisplayFilter != nil {
                Button { session.applyDisplayFilter("") } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .help("Сбросить фильтр")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(filterBackground)
    }

    private var filterBackground: Color {
        if session.displayFilterError != nil { return Color.red.opacity(0.18) }
        if session.activeDisplayFilter != nil { return Color.green.opacity(0.12) }
        return Color(nsColor: .controlBackgroundColor)
    }
}

struct StatusBarView: View {
    @Environment(CaptureSession.self) private var session

    var body: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(session.isCapturing ? Color.green : Color.secondary.opacity(0.4))
                .frame(width: 8, height: 8)
            Text(session.isCapturing ? "Захват: \(session.selectedInterface)" : "Остановлен")
            if !session.linkTypeName.isEmpty { Text(session.linkTypeName).foregroundStyle(.secondary) }
            Divider().frame(height: 12)
            let _ = session.revision
            Text("Пакетов: \(session.store.packets.count)")
            Text("Показано: \(session.store.visible.count)")
            if session.stats.dropped > 0 || session.stats.interfaceDropped > 0 {
                Text("Потеряно ядром: \(session.stats.dropped + session.stats.interfaceDropped)")
                    .foregroundStyle(.red)
                    .help("Пакеты отброшены BPF — буфер переполнен. Сузьте фильтр захвата.")
            }
            Spacer()
            if let err = session.displayFilterError {
                Text(err).foregroundStyle(.red).lineLimit(1)
            } else if !session.bpfPreview.isEmpty {
                Text("BPF: \(session.bpfPreview)").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Button { session.applyDisplayFilter("expert.error") } label: {
                Label("\(session.errorCount)", systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            }
            .buttonStyle(.borderless)
            .help("Пакеты с ошибками — показать")
            Button { session.applyDisplayFilter("expert.warning") } label: {
                Label("\(session.warningCount)", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            }
            .buttonStyle(.borderless)
            .help("Пакеты, требующие внимания — показать")
        }
        .font(.callout)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
    }
}
