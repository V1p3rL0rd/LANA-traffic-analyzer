import PacketCore
import SwiftUI

struct CaptureOptionsView: View {
    @Environment(CaptureSession.self) private var session
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        @Bindable var session = session
        VStack(spacing: 0) {
            HStack {
                Text("Фильтр захвата").font(.title2.bold())
                Spacer()
                Text(session.selectedInterface).foregroundStyle(.secondary)
            }
            .padding()

            HSplitView {
                Form {
                    Section("Адреса") {
                        TextField("srcaddr", text: $session.filterSpec.sourceAddresses,
                                  prompt: Text("192.168.1.10, 10.0.0.0/8, aa:bb:cc:dd:ee:ff, host.local"))
                        TextField("dstaddr", text: $session.filterSpec.destinationAddresses,
                                  prompt: Text("8.8.8.8, 2001:db8::/32"))
                        Toggle("В обе стороны (src ⇄ dst)", isOn: $session.filterSpec.bidirectional)
                            .help("Захватывать диалог целиком: A→B и B→A")
                    }
                    Section("Выбрано протоколов: \(session.filterSpec.protocolIDs.count)") {
                        if session.filterSpec.protocolIDs.isEmpty {
                            Text("Все протоколы").foregroundStyle(.secondary)
                        } else {
                            Text(session.filterSpec.protocolIDs.sorted().compactMap { ProtocolCatalog.byID[$0]?.name }.joined(separator: ", "))
                                .font(.callout)
                            Button("Сбросить выбор") { session.filterSpec.protocolIDs.removeAll() }
                        }
                    }
                    Section("Расширенный режим") {
                        Toggle("Свой BPF-фильтр", isOn: $session.filterSpec.useCustomBPF)
                        if session.filterSpec.useCustomBPF {
                            TextEditor(text: $session.filterSpec.customBPF)
                                .font(.system(.body, design: .monospaced))
                                .frame(minHeight: 60)
                        }
                        LabeledContent("BPF") {
                            Text(session.bpfPreview.isEmpty ? "(без фильтра — весь трафик)" : session.bpfPreview)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(6)
                        }
                        if let err = session.bpfError {
                            Label(err, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                        } else {
                            Label("Фильтр корректен", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        }
                    }
                    Section("Параметры") {
                        Toggle("Promiscuous mode", isOn: $session.promiscuous)
                        Toggle("Monitor mode (802.11, только Wi-Fi)", isOn: $session.monitorMode)
                            .disabled(session.interfaces.first { $0.name == session.selectedInterface }?.kind != .wifi)
                        Toggle("Проверять контрольные суммы", isOn: $session.validateChecksums)
                            .help("Исходящие пакеты на macOS часто имеют неверную сумму из-за checksum offload")
                        Stepper("Лимит в памяти: \(session.maxPackets.formatted()) пакетов",
                                value: $session.maxPackets, in: 100_000 ... 20_000_000, step: 500_000)
                    }
                }
                .formStyle(.grouped)
                .frame(minWidth: 380, idealWidth: 420)

                ProtocolPicker(selection: $session.filterSpec.protocolIDs, query: $session.protocolQuery)
                    .frame(minWidth: 340, idealWidth: 380)
            }

            Divider()
            HStack {
                Button("Сбросить всё") { session.filterSpec = CaptureFilterSpec() }
                Spacer()
                Button("Готово") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Начать захват") {
                    dismiss()
                    session.start()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(session.bpfError != nil || session.isCapturing)
            }
            .padding()
        }
        .frame(minWidth: 820, minHeight: 600)
    }
}

/// Searchable, category-grouped protocol checklist (≈190 protocols from `ProtocolCatalog`).
struct ProtocolPicker: View {
    @Binding var selection: Set<String>
    @Binding var query: String

    var body: some View {
        VStack(spacing: 0) {
            TextField("Поиск протокола или порта…", text: $query)
                .textFieldStyle(.roundedBorder)
                .padding(8)
            List {
                ForEach(ProtocolCatalog.grouped(matching: query)) { group in
                    Section {
                        ForEach(group.items) { p in
                            Toggle(isOn: binding(p.id)) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(p.name)
                                    Text(caption(p)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                }
                            }
                            .toggleStyle(.checkbox)
                        }
                    } header: {
                        HStack {
                            Text(group.category.rawValue)
                            Spacer()
                            Button(allSelected(group.items) ? "Снять" : "Все") { toggleAll(group.items) }
                                .buttonStyle(.borderless).font(.caption)
                        }
                    }
                }
            }
            .listStyle(.sidebar)
        }
    }

    private func caption(_ p: ProtocolDescriptor) -> String {
        var parts: [String] = []
        if !p.tcpPorts.isEmpty { parts.append("tcp " + p.tcpPorts.map(String.init).joined(separator: ",")) }
        if !p.udpPorts.isEmpty { parts.append("udp " + p.udpPorts.map(String.init).joined(separator: ",")) }
        if parts.isEmpty { parts.append(p.bpf) }
        if !p.summary.isEmpty { parts.append(p.summary) }
        return parts.joined(separator: " · ")
    }

    private func binding(_ id: String) -> Binding<Bool> {
        Binding(get: { selection.contains(id) },
                set: { on in if on { selection.insert(id) } else { selection.remove(id) } })
    }

    private func allSelected(_ items: [ProtocolDescriptor]) -> Bool { items.allSatisfy { selection.contains($0.id) } }

    private func toggleAll(_ items: [ProtocolDescriptor]) {
        if allSelected(items) { items.forEach { selection.remove($0.id) } } else { items.forEach { selection.insert($0.id) } }
    }
}
