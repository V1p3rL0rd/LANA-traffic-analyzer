<p align="center">
  <img src="Assets/AppIcon.png" width="160" alt="LANA Traffic Analyzer icon">
</p>

<h1 align="center">LANA Traffic Analyzer</h1>
<p align="center"><b>Нативный анализатор сетевого трафика для macOS</b> — функции в духе Wireshark без перегруженного интерфейса. Компаньон <a href="https://github.com/V1p3rL0rd/LANA-scanner">LANA Scanner</a>.</p>

<p align="center">
  <img alt="macOS 14+" src="https://img.shields.io/badge/macOS-14%2B-black?logo=apple">
  <img alt="Swift 5.9+" src="https://img.shields.io/badge/Swift-5.9%2B-F05138?logo=swift&logoColor=white">
  <img alt="Xcode не нужен" src="https://img.shields.io/badge/Xcode-%D0%BD%D0%B5%20%D0%BD%D1%83%D0%B6%D0%B5%D0%BD-2FE6B0">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.md">English version</a></p>

---

SwiftUI + AppKit, libpcap, собственные диссекторы на Swift. macOS 14+, Apple Silicon (Intel — через `--universal` при наличии полного Xcode).

## Архитектура

```
 /dev/bpf* ──► libpcap (CaptureEngine, поток "lana.capture")
                   │  батчи RawPacket (pcap_dispatch, immediate mode)
                   ▼
        CapturePipeline (serial queue "lana.analysis")
          Dissector (stateless, L2→L7)  ──►  AnomalyEngine (stateful: TCP, ARP, сканы)
          + live display filter                     │ ExpertInfo (error / warning / note)
                   │  pending buffer (lock)         ▼
                   ▼
        CaptureSession (@MainActor, drain 4 Гц) ──► NSTableView (подсветка строк)
                                                 ├─► дерево протоколов + hex (пере-диссекция по клику)
                                                 └─► панель аномалий (агрегаты)
```

Ключевые решения:

| Решение | Почему |
|---|---|
| libpcap вместо прямого BPF ioctl | `pcap_compile` даёт полноценный BPF-синтаксис, pcap/pcapng I/O и DLT разных интерфейсов из коробки; входит в macOS SDK |
| Собственные диссекторы | без GPL-зависимостей и установки Wireshark; ~45 протоколов разбираются полностью, остальные из каталога (185 шт.) опознаются по порту/EtherType |
| Хранится только `RawPacket` + `PacketSummary` | дерево протоколов строится заново по клику — память ≈ размер трафика + ~200 Б на пакет |
| NSTableView вместо SwiftUI `Table` | миллионы строк без лагов и подсветка всей строки (SwiftUI Table на macOS 14 так не умеет) |
| ChmodBPF (группа `access_bpf`) | GUI не работает под root; та же модель, что у Wireshark, совместима с его установкой |

### Поддерживаемые интерфейсы (DLT)

| Интерфейс | DLT | Разбор |
|---|---|---|
| `en*` Ethernet / Wi-Fi | EN10MB | Ethernet II, 802.3/LLC/SNAP, VLAN/Q-in-Q |
| `en*` в monitor mode | IEEE802_11_RADIO | Radiotap + 802.11 (mgmt/ctrl/data, SSID, deauth) |
| `lo0` | NULL | BSD loopback |
| `utun*`, `ipsec*` (VPN, WireGuard, Tailscale) | RAW / NULL | IPv4/IPv6 |
| `bridge*`, `vmenet*`, `awdl0`, `llw0` | EN10MB | как Ethernet |
| pcap/pcapng-файлы | + LINUX_SLL/SLL2, PPP | Linux cooked capture, PPP |

### Разбор протоколов

- **L2:** Ethernet, LLC/SNAP, 802.1Q/ad, ARP/RARP, MPLS, PPPoE, LLDP, CDP, STP/RSTP/MSTP, LACP, EAPOL, 802.11
- **L3:** IPv4 (опции, фрагменты), IPv6 (цепочка extension headers), ICMP, ICMPv6/NDP/MLD, IGMP, GRE (вкл. ERSPAN/PPTP), ESP, AH, IP-in-IP, 6in4
- **Маршрутизация:** OSPF, VRRP, BGP, RIP, BFD, PIM/EIGRP (заголовок)
- **L4:** TCP (флаги, опции, анализ последовательности), UDP, SCTP (чанки)
- **L7:** DNS/mDNS/LLMNR/NBNS, DHCP/DHCPv6, NTP, SNMP, Syslog, TFTP, HTTP/1.x, TLS (SNI, ALPN, версия, alerts), QUIC, SSH, FTP, SMTP, POP3, IMAP, Telnet, SIP, RTSP, SSDP, Redis, MQTT, Modbus/TCP, Kafka, WireGuard, VXLAN, Geneve, STUN, IKE/NAT-T, RADIUS

Протокол на нестандартном порту определяется эвристиками (TLS-запись, HTTP-метод, SSH-баннер, QUIC long header).

### Подсветка аномалий

Красный — ошибка, жёлтый — требует внимания. Полный список — в панели «Аномалии» (⌥⌘I).

| 🔴 Ошибка | 🟡 Внимание |
|---|---|
| Malformed/усечённые заголовки, неверные checksum* | TCP retransmission / fast / spurious, out-of-order, dup ACK |
| TCP RST, Zero Window | Previous segment not captured, Window Full, Zero Window Probe, SYN retransmission |
| SYN+FIN, NULL, Xmas-сканы; LAND (src == dst) | FIN-scan, port scan (>100 целей / 5 с), ping sweep |
| ARP: смена MAC у IP (спуфинг) | Gratuitous ARP reply, ICMP/ICMPv6 redirect |
| ICMP unreachable, parameter problem | ICMP TTL exceeded, PMTU / Packet Too Big |
| DNS SERVFAIL/REFUSED/FORMERR | DNS NXDOMAIN, TC, AXFR, подозрительно длинные имена (туннелирование) |
| HTTP/SIP 5xx, TLS fatal alert, SMTP/FTP 5xx | HTTP 4xx, TLS warning alert, TLS ≤1.1, слабый шифр, Heartbeat |
| DHCP NAK, EAP failure, RADIUS reject, BGP NOTIFICATION, BFD down | Открытые учётные данные: HTTP Basic, FTP/POP3 PASS, IMAP LOGIN, Telnet, SNMP v1/v2c community |
| IPv6 RH0, Tiny fragment, TTL 0 | IPv4/IPv6 фрагментация, TTL=1, STP TCN, VRRP prio 0, 802.11 deauth |

\* Проверка checksum по умолчанию выключена: на macOS исходящие пакеты захватываются до checksum offload и выглядят «битыми». Включается в параметрах захвата.

## Установка готовой версии

1. Скачайте `LANA-Traffic-Analyzer-<версия>-macOS.zip` со страницы [Releases](../../releases) и распакуйте.
2. Перенесите **LANA Traffic Analyzer.app** в «Программы».
3. Приложение подписано ad-hoc и не нотаризовано, поэтому при первом запуске Gatekeeper его заблокирует. Откройте через ПКМ → «Открыть», или через *Системные настройки → Конфиденциальность и безопасность → «Всё равно открыть»*, или командой:
   ```bash
   xattr -dr com.apple.quarantine "/Applications/LANA Traffic Analyzer.app"
   ```
4. Дайте доступ к захвату пакетов (один раз) — см. [Доступ к захвату пакетов](#доступ-к-захвату-пакетов). Если у вас установлен Wireshark с ChmodBPF, доступ уже есть.

## Сборка из исходников

Нужны macOS 14+ и Xcode Command Line Tools (`xcode-select --install`) — Swift 5.9 или новее. Полный Xcode не обязателен: интерфейс не использует SwiftUI-макросы (`@State`, `#Preview`), плагины которых поставляются только с Xcode.

```bash
git clone https://github.com/V1p3rL0rd/LANA-traffic-analyzer.git && cd LANA-traffic-analyzer
./Scripts/build-app.sh            # → "build/LANA Traffic Analyzer.app" (ad-hoc подпись)
./Scripts/build-app.sh --install  # + установка в /Applications (INSTALL_DIR=~/Applications — только для себя)
open "/Applications/LANA Traffic Analyzer.app"
```

| Команда | Результат |
|---|---|
| `./Scripts/build-app.sh` | `build/LANA Traffic Analyzer.app` под архитектуру вашего Mac |
| `./Scripts/build-app.sh --install` | сборка + установка в `/Applications` (появится в Launchpad и Spotlight) |
| `./Scripts/build-app.sh --universal` | бинарь arm64 + x86_64 (нужен полный Xcode) |
| `INSTALL_DIR=~/Applications ./Scripts/build-app.sh --install` | установка только для текущего пользователя |
| `swift test` | юнит-тесты ядра |

Собирайте под своим пользователем, не под root: скрипт откажется работать от root, потому что `.build/` и `build/` стали бы принадлежать root и следующая сборка упала бы с `Permission denied`.

## Доступ к захвату пакетов

Захват идёт через `/dev/bpf*`, а они по умолчанию доступны только root. Запускать GUI под root плохая идея, поэтому используется та же схема, что у Wireshark: группа `access_bpf` и служба, которая при загрузке выдаёт этой группе права на BPF-устройства.

```bash
sudo ./Scripts/install-chmodbpf.sh      # идемпотентно; совместимо с ChmodBPF от Wireshark
# выйдите из системы и войдите снова, чтобы применилась группа access_bpf
ls -l /dev/bpf0                         # crw-rw----  root  access_bpf
```

Откат: `sudo ./Scripts/uninstall-chmodbpf.sh [--remove-group]`. Если установлен ChmodBPF от Wireshark, права и группа не трогаются.

## Важно знать (ограничения и подводные камни)

1. **App Sandbox отключён намеренно:** из sandbox открыть `/dev/bpf*` нельзя. Поэтому дистрибуция только вне App Store.
2. **Группа `access_bpf`** даёт право прослушивать весь трафик хоста. Добавляйте туда только доверенные учётные записи.
3. **Контрольные суммы** по умолчанию не проверяются: исходящие пакеты на macOS захватываются до checksum offload и выглядели бы «битыми». Включается в параметрах захвата.
4. **Память.** Пакеты хранятся в памяти (по умолчанию до 2 млн), при достижении лимита захват останавливается с уведомлением. Для многочасовых захватов используйте `tcpdump -G/-C` с ротацией и открывайте файлы в LANA Traffic Analyzer.
5. **Фрагменты IP и TCP-потоки не собираются:** протокол, сообщение которого разбито на несколько сегментов, разбирается по первому сегменту.
6. **Monitor mode** (802.11) доступен только для Wi-Fi-интерфейса и на время захвата отключает его от сети.
7. **Юридически:** анализируйте только сети, на которые у вас есть права.

## Работа с программой

**Фильтр захвата (⌘K)** — компилируется в BPF и работает в ядре, то есть до копирования пакетов:

- `srcaddr` / `dstaddr` — IPv4, IPv6, CIDR, MAC, имя хоста; несколько значений через запятую (OR)
- «В обе стороны» — захват диалога целиком (A→B и B→A)
- протоколы — 185 штук в 18 категориях, с поиском по имени и номеру порта
- «Свой BPF» — произвольное выражение; проверяется через `pcap_compile` прямо при вводе

Адреса строго валидируются: строка `1.2.3.4 or port 22` будет отклонена, так что подставить лишние BPF-примитивы через поле адреса нельзя.

**Display filter** — синтаксис как у Wireshark (подмножество):

```
ip.addr == 10.0.0.0/8 && tcp.port in {80 443}
dns.qry.name contains "apple" || !arp
http.response.code >= 400
tcp.analysis.retransmission || tcp.analysis.zero_window
expert.error            expert.warning          expert.group == security
tls.handshake.extensions_server_name matches "\.ru$"
```

Операторы: `== != > < >= <=` (`eq ne gt lt ge le`), `contains`, `matches`/`~` (regex), `in {…}`, `&& || !` (`and or not`), скобки. Через контекстное меню строки: фильтр по источнику, назначению, протоколу или диалогу.

**Файлы:** открытие pcap/pcapng (⌘O), сохранение всего (⌘S) или только отображаемых (⇧⌘S) в pcap.

## Проверка

```bash
# 1. права на BPF
ls -l /dev/bpf0                 # crw-rw----  root  access_bpf
id -Gn | tr ' ' '\n' | grep access_bpf

# 2. юнит-тесты: диссекторы, TCP-анализ (вкл. wrap-around seq), ARP-спуфинг, BPF всех 185 протоколов,
#    display filter, pcap round-trip, fuzz на усечённых и случайных кадрах
swift test

# 3. сверка с эталоном (нужен tcpdump/tshark)
sudo tcpdump -i en0 -c 2000 -w /tmp/ref.pcap
# открыть /tmp/ref.pcap в LANA Traffic Analyzer (⌘O); число пакетов должно совпасть с:
tcpdump -r /tmp/ref.pcap 2>/dev/null | wc -l

# 4. проверка подсветки аномалий
curl -s http://127.0.0.1:1 || true      # RST → красная строка (захват на lo0)
dig nonexistent.invalid                  # NXDOMAIN → жёлтая строка
```

## Эксплуатация

- **Логи:** `log stream --predicate 'subsystem == "app.lana"'` (старт/стоп захвата, ошибки pcap).
- **Потери пакетов:** строка состояния показывает «Потеряно ядром» (`pcap_stats` ps_drop + ps_ifdrop). Если растёт — сузьте фильтр захвата: BPF отбрасывает лишнее в ядре. Буфер 16 МБ ограничен `sysctl debug.bpf_maxbufsize`.
- **Откат:** приложение не хранит ничего критичного. Удалить: `/Applications/LANA Traffic Analyzer.app`, настройки — `defaults delete app.lana.LANA`, права на BPF — `sudo ./Scripts/uninstall-chmodbpf.sh`.
- **Обновление:** `git pull && ./Scripts/build-app.sh --install` — старая версия в `/Applications` заменяется атомарно.

## Структура

```
Sources/CPcap/             module map для libpcap
Sources/PacketCore/        платформенно-независимое ядро
  Capture/                 CaptureEngine, InterfaceDiscovery, PcapFile, BPFValidator
  Dissect/                 L2, IP, ICMP, Transport, DNS, DHCP, TLS/QUIC, Text (HTTP…), Misc, WLAN
  Analysis/                AnomalyEngine (TCP/ARP/сканы), PacketProcessor
  Filter/                  ProtocolCatalog, CaptureFilter (→BPF), DisplayFilter
Sources/LANA/              SwiftUI-приложение
Tests/PacketCoreTests/     XCTest
Scripts/                   build-app.sh, install/uninstall-chmodbpf.sh
Assets/                    иконка (исходник SVG + .png + .icns)
.github/workflows/         CI (тесты + сборка) и релиз (опубликованный релиз → zip с .app)
```

## Релиз

Откройте **Releases → Draft a new release**, создайте тег, например `v1.0.0`, нажмите **Generate release notes** и **Publish**. Через несколько минут GitHub Actions соберёт universal-приложение и прикрепит к релизу `LANA-Traffic-Analyzer-<версия>-macOS.zip` с контрольной суммой SHA-256.

## Лицензия

[MIT](LICENSE) © 2026 Vianor Gvazbaya
