import AppKit
import SwiftUI
import UniformTypeIdentifiers

@main
struct LANAApp: App {
    private let session = CaptureSession.shared

    init() {
        // Needed when launched via `swift run` (no bundle): become a regular foreground app.
        NSApplication.shared.setActivationPolicy(.regular)
        DispatchQueue.main.async { NSApp.activate(ignoringOtherApps: true) }
    }

    var body: some Scene {
        WindowGroup("LANA Traffic Analyzer") {
            ContentView()
                .environment(session)
                .frame(minWidth: 1000, minHeight: 640)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .newItem) {
                Button("Открыть…") { FileActions.open(session) }.keyboardShortcut("o")
                Button("Сохранить как…") { FileActions.save(session, displayedOnly: false) }.keyboardShortcut("s")
                Button("Экспорт отображаемых…") { FileActions.save(session, displayedOnly: true) }.keyboardShortcut("s", modifiers: [.command, .shift])
            }
            CommandMenu("Захват") {
                Button(session.isCapturing ? "Остановить" : "Начать") { session.toggleCapture() }.keyboardShortcut("e")
                Button("Параметры захвата…") { session.showCaptureOptions = true }.keyboardShortcut("k")
                Button("Очистить") { session.clear() }.keyboardShortcut("l").disabled(session.isCapturing)
                Divider()
                Button("Обновить список интерфейсов") { session.refreshInterfaces() }
            }
            CommandMenu("Анализ") {
                Button("Только ошибки") { session.applyDisplayFilter("expert.error") }
                Button("Ошибки и предупреждения") { session.applyDisplayFilter("expert.error || expert.warning") }
                Button("Проблемы TCP") { session.applyDisplayFilter("tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.zero_window || tcp.analysis.lost_segment || tcp.connection.rst") }
                Button("Сбросить фильтр") { session.applyDisplayFilter("") }.keyboardShortcut(.escape, modifiers: [.command])
                Divider()
                Button("Панель аномалий") { session.showExpert.toggle() }.keyboardShortcut("i", modifiers: [.command, .option])
            }
        }
    }
}

@MainActor
enum FileActions {
    static let types: [UTType] = [UTType(filenameExtension: "pcap"), UTType(filenameExtension: "pcapng"),
                                  UTType(filenameExtension: "cap")].compactMap { $0 }

    static func open(_ session: CaptureSession) {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = types
        panel.allowsOtherFileTypes = true
        if panel.runModal() == .OK, let url = panel.url { session.open(url) }
    }

    static func save(_ session: CaptureSession, displayedOnly: Bool) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = types.prefix(1).map { $0 }
        panel.nameFieldStringValue = "capture-\(Int(Date().timeIntervalSince1970)).pcap"
        if panel.runModal() == .OK, let url = panel.url { session.save(to: url, displayedOnly: displayedOnly) }
    }
}
