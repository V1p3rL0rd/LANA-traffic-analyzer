import Foundation

public enum ProtocolCategory: String, CaseIterable, Sendable, Identifiable {
    case link = "Канальный уровень (L2)"
    case network = "Сетевой уровень (L3)"
    case routing = "Маршрутизация и резервирование"
    case transport = "Транспортный уровень (L4)"
    case tunnel = "Туннели и VPN"
    case naming = "Имена и адресация"
    case web = "Web"
    case mail = "Почта"
    case files = "Передача файлов и хранилища"
    case remote = "Удалённый доступ"
    case auth = "Каталоги и аутентификация"
    case database = "Базы данных и кэши"
    case messaging = "Брокеры сообщений и IoT"
    case management = "Мониторинг и управление"
    case voip = "Голос и видео"
    case industrial = "Промышленные (ICS/SCADA)"
    case discovery = "Обнаружение сервисов"
    case cloud = "Оркестрация и облако"

    public var id: String { rawValue }
}

public struct ProtocolGroup: Identifiable, Sendable {
    public let category: ProtocolCategory
    public let items: [ProtocolDescriptor]
    public var id: String { category.id }
}

public struct ProtocolDescriptor: Identifiable, Sendable, Hashable {
    public let id: String          // display-filter abbreviation
    public let name: String
    public let category: ProtocolCategory
    public let tcpPorts: [UInt16]
    public let udpPorts: [UInt16]
    public let customBPF: String?
    public let summary: String

    /// BPF expression selecting this protocol. Port-based protocols match their IANA/well-known
    /// ports only — traffic on non-standard ports needs a display filter instead.
    public var bpf: String {
        if let customBPF { return customBPF }
        var parts: [String] = []
        if !tcpPorts.isEmpty {
            parts.append("(tcp and (" + tcpPorts.map { "port \($0)" }.joined(separator: " or ") + "))")
        }
        if !udpPorts.isEmpty {
            parts.append("(udp and (" + udpPorts.map { "port \($0)" }.joined(separator: " or ") + "))")
        }
        return parts.count == 1 ? parts[0] : "(" + parts.joined(separator: " or ") + ")"
    }
}

private func P(_ id: String, _ name: String, _ cat: ProtocolCategory, tcp: [UInt16] = [], udp: [UInt16] = [],
               bpf: String? = nil, _ summary: String = "") -> ProtocolDescriptor {
    ProtocolDescriptor(id: id, name: name, category: cat, tcpPorts: tcp, udpPorts: udp, customBPF: bpf, summary: summary)
}

public enum ProtocolCatalog {
    public static let all: [ProtocolDescriptor] = [
        // L2
        P("eth", "Ethernet II / 802.3", .link, bpf: "ether[0] & 0 = 0", "Все Ethernet-кадры"),
        P("arp", "ARP", .link, bpf: "arp", "Address Resolution Protocol"),
        P("rarp", "RARP", .link, bpf: "rarp"),
        P("vlan", "802.1Q VLAN", .link, bpf: "vlan"),
        P("qinq", "802.1ad Q-in-Q", .link, bpf: "ether proto 0x88a8"),
        P("lldp", "LLDP", .link, bpf: "ether proto 0x88cc", "Link Layer Discovery Protocol"),
        P("cdp", "CDP", .link, bpf: "ether dst 01:00:0c:cc:cc:cc", "Cisco Discovery Protocol"),
        P("stp", "STP / RSTP / MSTP", .link, bpf: "ether dst 01:80:c2:00:00:00", "Spanning Tree"),
        P("lacp", "LACP / Slow Protocols", .link, bpf: "ether proto 0x8809"),
        P("eapol", "EAPOL (802.1X)", .link, bpf: "ether proto 0x888e"),
        P("pppoed", "PPPoE Discovery", .link, bpf: "ether proto 0x8863"),
        P("pppoes", "PPPoE Session", .link, bpf: "pppoes"),
        P("mpls", "MPLS", .link, bpf: "mpls"),
        P("macsec", "MACsec (802.1AE)", .link, bpf: "ether proto 0x88e5"),
        P("ptp", "PTP (IEEE 1588)", .link, udp: [319, 320], bpf: "(ether proto 0x88f7 or (udp and (port 319 or port 320)))"),
        P("ethercat", "EtherCAT", .industrial, bpf: "ether proto 0x88a4"),
        P("profinet", "PROFINET RT", .industrial, bpf: "ether proto 0x8892"),
        P("wlan", "IEEE 802.11 (monitor mode)", .link, bpf: "type mgt or type ctl or type data", "Только в режиме мониторинга Wi-Fi"),
        P("wlan_mgt", "802.11 Management", .link, bpf: "type mgt"),
        P("wlan_beacon", "802.11 Beacon", .link, bpf: "type mgt subtype beacon"),

        // L3
        P("ip", "IPv4", .network, bpf: "ip"),
        P("ipv6", "IPv6", .network, bpf: "ip6"),
        P("icmp", "ICMP", .network, bpf: "icmp"),
        P("icmpv6", "ICMPv6 (вкл. NDP)", .network, bpf: "icmp6"),
        P("igmp", "IGMP", .network, bpf: "igmp"),
        P("ip_frag", "IPv4 фрагменты", .network, bpf: "ip and (ip[6:2] & 0x3fff != 0)"),
        P("ndp", "IPv6 Neighbor Discovery", .network, bpf: "icmp6 and (ip6[40] >= 133 and ip6[40] <= 137)"),
        P("ipx", "IPX", .network, bpf: "ipx"),

        // Routing / FHRP
        P("ospf", "OSPF", .routing, bpf: "(ip proto 89 or ip6 proto 89)"),
        P("eigrp", "EIGRP", .routing, bpf: "(ip proto 88 or ip6 proto 88)"),
        P("bgp", "BGP", .routing, tcp: [179]),
        P("rip", "RIP v1/v2", .routing, udp: [520]),
        P("ripng", "RIPng", .routing, udp: [521]),
        P("isis", "IS-IS", .routing, bpf: "iso proto 0x83"),
        P("pim", "PIM", .routing, bpf: "(ip proto 103 or ip6 proto 103)"),
        P("vrrp", "VRRP", .routing, bpf: "(ip proto 112 or ip6 proto 112)"),
        P("hsrp", "HSRP", .routing, udp: [1985, 2029]),
        P("glbp", "GLBP", .routing, udp: [3222]),
        P("carp", "CARP", .routing, bpf: "ip proto 112 and ether dst 01:00:5e:00:00:12"),
        P("bfd", "BFD", .routing, udp: [3784, 3785, 4784]),
        P("ldp", "LDP", .routing, tcp: [646], udp: [646]),
        P("rsvp", "RSVP", .routing, bpf: "ip proto 46"),

        // L4
        P("tcp", "TCP", .transport, bpf: "tcp"),
        P("udp", "UDP", .transport, bpf: "udp"),
        P("sctp", "SCTP", .transport, bpf: "sctp"),
        P("dccp", "DCCP", .transport, bpf: "(ip proto 33 or ip6 proto 33)"),
        P("tcp_syn", "TCP SYN (новые соединения)", .transport, bpf: "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0"),
        P("tcp_rst", "TCP RST", .transport, bpf: "tcp[tcpflags] & tcp-rst != 0"),

        // Tunnels / VPN
        P("gre", "GRE", .tunnel, bpf: "(ip proto 47 or ip6 proto 47)"),
        P("ipip", "IP-in-IP", .tunnel, bpf: "(ip proto 4 or ip6 proto 4)"),
        P("6in4", "IPv6-in-IPv4 (6in4/6to4)", .tunnel, bpf: "ip proto 41"),
        P("esp", "IPsec ESP", .tunnel, bpf: "(ip proto 50 or ip6 proto 50)"),
        P("ah", "IPsec AH", .tunnel, bpf: "(ip proto 51 or ip6 proto 51)"),
        P("isakmp", "IKE / ISAKMP (+NAT-T)", .tunnel, udp: [500, 4500]),
        P("wg", "WireGuard", .tunnel, udp: [51820]),
        P("openvpn", "OpenVPN", .tunnel, tcp: [1194], udp: [1194]),
        P("l2tp", "L2TP", .tunnel, udp: [1701], bpf: "((udp and port 1701) or ip proto 115)"),
        P("pptp", "PPTP", .tunnel, tcp: [1723]),
        P("vxlan", "VXLAN", .tunnel, udp: [4789]),
        P("geneve", "Geneve", .tunnel, udp: [6081]),
        P("gtp", "GTP-U / GTP-C", .tunnel, udp: [2152, 2123]),
        P("teredo", "Teredo", .tunnel, udp: [3544]),
        P("tailscale", "Tailscale / DERP", .tunnel, udp: [41641]),

        // Naming / addressing
        P("dns", "DNS", .naming, tcp: [53], udp: [53]),
        P("mdns", "mDNS (Bonjour)", .naming, udp: [5353]),
        P("llmnr", "LLMNR", .naming, tcp: [5355], udp: [5355]),
        P("nbns", "NetBIOS Name Service", .naming, udp: [137]),
        P("dhcp", "DHCP / BOOTP", .naming, udp: [67, 68]),
        P("dhcpv6", "DHCPv6", .naming, udp: [546, 547]),
        P("dot", "DNS over TLS", .naming, tcp: [853]),
        P("ntp", "NTP", .naming, udp: [123]),
        P("nts", "NTS-KE", .naming, tcp: [4460]),
        P("whois", "WHOIS", .naming, tcp: [43]),

        // Web
        P("http", "HTTP", .web, tcp: [80, 8000, 8008, 8080, 8888]),
        P("tls", "TLS / HTTPS", .web, tcp: [443, 8443]),
        P("quic", "QUIC / HTTP/3", .web, udp: [443, 8443]),
        P("http_proxy", "HTTP Proxy", .web, tcp: [3128, 8118]),
        P("socks", "SOCKS", .web, tcp: [1080]),
        P("websocket", "WebSocket (HTTP Upgrade)", .web, tcp: [80, 443]),
        P("grpc", "gRPC (часто 50051)", .web, tcp: [50051]),

        // Mail
        P("smtp", "SMTP", .mail, tcp: [25, 587]),
        P("smtps", "SMTPS", .mail, tcp: [465]),
        P("pop", "POP3", .mail, tcp: [110]),
        P("pop3s", "POP3S", .mail, tcp: [995]),
        P("imap", "IMAP", .mail, tcp: [143]),
        P("imaps", "IMAPS", .mail, tcp: [993]),

        // Files / storage
        P("ftp", "FTP", .files, tcp: [21]),
        P("ftp-data", "FTP-DATA", .files, tcp: [20]),
        P("ftps", "FTPS", .files, tcp: [989, 990]),
        P("tftp", "TFTP", .files, udp: [69]),
        P("smb", "SMB / CIFS", .files, tcp: [445]),
        P("nbss", "NetBIOS Session", .files, tcp: [139]),
        P("nfs", "NFS", .files, tcp: [2049], udp: [2049]),
        P("portmap", "RPC Portmapper", .files, tcp: [111], udp: [111]),
        P("afp", "AFP", .files, tcp: [548]),
        P("rsync", "rsync", .files, tcp: [873]),
        P("iscsi", "iSCSI", .files, tcp: [3260]),
        P("webdav", "WebDAV / HTTP alt", .files, tcp: [8081]),
        P("git", "Git protocol", .files, tcp: [9418]),
        P("ipp", "IPP (печать)", .files, tcp: [631]),
        P("lpd", "LPD", .files, tcp: [515]),
        P("jetdirect", "HP JetDirect", .files, tcp: [9100]),

        // Remote access
        P("ssh", "SSH / SFTP / SCP", .remote, tcp: [22]),
        P("telnet", "Telnet", .remote, tcp: [23]),
        P("rdp", "RDP", .remote, tcp: [3389], udp: [3389]),
        P("vnc", "VNC / RFB", .remote, tcp: [5900, 5901]),
        P("x11", "X11", .remote, tcp: [6000, 6001]),
        P("rlogin", "rlogin / rsh", .remote, tcp: [513, 514]),
        P("winrm", "WinRM", .remote, tcp: [5985, 5986]),
        P("ard", "Apple Remote Desktop", .remote, tcp: [3283], udp: [3283]),

        // Directory / auth
        P("ldap", "LDAP", .auth, tcp: [389], udp: [389]),
        P("ldaps", "LDAPS", .auth, tcp: [636]),
        P("gc", "AD Global Catalog", .auth, tcp: [3268, 3269]),
        P("kerberos", "Kerberos", .auth, tcp: [88], udp: [88]),
        P("kpasswd", "Kerberos kpasswd", .auth, tcp: [464], udp: [464]),
        P("radius", "RADIUS", .auth, udp: [1812, 1813, 1645, 1646]),
        P("tacplus", "TACACS+", .auth, tcp: [49]),
        P("diameter", "Diameter", .auth, tcp: [3868]),
        P("dcerpc", "DCE/RPC Endpoint Mapper", .auth, tcp: [135]),
        P("vault", "HashiCorp Vault", .auth, tcp: [8200]),

        // Databases / caches
        P("mysql", "MySQL / MariaDB", .database, tcp: [3306]),
        P("pgsql", "PostgreSQL", .database, tcp: [5432]),
        P("tds", "MS SQL (TDS)", .database, tcp: [1433]),
        P("tns", "Oracle TNS", .database, tcp: [1521]),
        P("mongo", "MongoDB", .database, tcp: [27017]),
        P("redis", "Redis", .database, tcp: [6379]),
        P("memcache", "Memcached", .database, tcp: [11211], udp: [11211]),
        P("cassandra", "Cassandra CQL", .database, tcp: [9042]),
        P("elasticsearch", "Elasticsearch", .database, tcp: [9200, 9300]),
        P("clickhouse", "ClickHouse", .database, tcp: [8123, 9000]),
        P("couchdb", "CouchDB", .database, tcp: [5984]),
        P("influxdb", "InfluxDB", .database, tcp: [8086]),

        // Messaging / IoT
        P("kafka", "Apache Kafka", .messaging, tcp: [9092]),
        P("amqp", "AMQP (RabbitMQ)", .messaging, tcp: [5672, 5671]),
        P("mqtt", "MQTT", .messaging, tcp: [1883, 8883]),
        P("coap", "CoAP", .messaging, udp: [5683, 5684]),
        P("stomp", "STOMP", .messaging, tcp: [61613]),
        P("nats", "NATS", .messaging, tcp: [4222]),
        P("zmtp", "ZeroMQ", .messaging, tcp: [5555]),
        P("xmpp", "XMPP / Jabber", .messaging, tcp: [5222, 5269]),
        P("irc", "IRC", .messaging, tcp: [6667, 6697]),

        // Management / monitoring
        P("snmp", "SNMP", .management, udp: [161]),
        P("snmptrap", "SNMP Trap", .management, udp: [162]),
        P("syslog", "Syslog", .management, tcp: [601, 6514], udp: [514]),
        P("netflow", "NetFlow / IPFIX", .management, udp: [2055, 4739, 9995, 9996]),
        P("sflow", "sFlow", .management, udp: [6343]),
        P("zabbix", "Zabbix agent/server", .management, tcp: [10050, 10051]),
        P("prometheus", "Prometheus / node_exporter", .management, tcp: [9090, 9100, 9093]),
        P("grafana", "Grafana / Loki", .management, tcp: [3000, 3100]),
        P("netconf", "NETCONF", .management, tcp: [830]),
        P("gnmi", "gNMI", .management, tcp: [9339]),
        P("ipmi", "IPMI / RMCP", .management, udp: [623]),
        P("wol", "Wake-on-LAN", .management, udp: [7, 9], bpf: "(ether proto 0x0842 or (udp and (port 7 or port 9)))"),
        P("icap", "ICAP", .management, tcp: [1344]),
        P("mikrotik", "MikroTik Winbox/API", .management, tcp: [8291, 8728, 8729]),
        P("capwap", "CAPWAP", .management, udp: [5246, 5247]),

        // VoIP / media
        P("sip", "SIP", .voip, tcp: [5060, 5061], udp: [5060]),
        P("rtp", "RTP/RTCP (типичный диапазон)", .voip, bpf: "udp and portrange 16384-32767"),
        P("rtsp", "RTSP", .voip, tcp: [554], udp: [554]),
        P("h323", "H.323 / H.225", .voip, tcp: [1720]),
        P("mgcp", "MGCP", .voip, udp: [2427, 2727]),
        P("iax2", "IAX2", .voip, udp: [4569]),
        P("stun", "STUN / TURN", .voip, tcp: [3478, 5349], udp: [3478, 5349]),
        P("rtmp", "RTMP", .voip, tcp: [1935]),

        // Industrial
        P("modbus", "Modbus/TCP", .industrial, tcp: [502]),
        P("dnp3", "DNP3", .industrial, tcp: [20000], udp: [20000]),
        P("s7comm", "Siemens S7 (COTP/TPKT)", .industrial, tcp: [102]),
        P("bacnet", "BACnet/IP", .industrial, udp: [47808]),
        P("opcua", "OPC UA", .industrial, tcp: [4840]),
        P("enip", "EtherNet/IP (CIP)", .industrial, tcp: [44818], udp: [2222, 44818]),
        P("iec104", "IEC 60870-5-104", .industrial, tcp: [2404]),

        // Discovery
        P("ssdp", "SSDP / UPnP", .discovery, udp: [1900]),
        P("wsdd", "WS-Discovery", .discovery, udp: [3702]),
        P("nbdgm", "NetBIOS Datagram", .discovery, udp: [138]),
        P("slp", "SLP", .discovery, tcp: [427], udp: [427]),
        P("bcast", "Broadcast / Multicast", .discovery, bpf: "broadcast or multicast"),

        // Cloud / orchestration
        P("k8s_api", "Kubernetes API", .cloud, tcp: [6443]),
        P("kubelet", "Kubelet", .cloud, tcp: [10250]),
        P("etcd", "etcd", .cloud, tcp: [2379, 2380]),
        P("docker", "Docker API", .cloud, tcp: [2375, 2376]),
        P("consul", "Consul", .cloud, tcp: [8300, 8301, 8500], udp: [8301]),
        P("nomad", "Nomad", .cloud, tcp: [4646, 4647]),
        P("proxmox", "Proxmox VE (UI/API)", .cloud, tcp: [8006]),
        P("vmware", "VMware vSphere / ESXi", .cloud, tcp: [902, 903]),
        P("ceph", "Ceph MON", .cloud, tcp: [3300, 6789]),
    ]

    public static let byID: [String: ProtocolDescriptor] = Dictionary(all.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

    /// Port → descriptor maps, used to label payloads that have no dedicated dissector.
    public static let tcpPortMap: [UInt16: ProtocolDescriptor] = portMap(\.tcpPorts)
    public static let udpPortMap: [UInt16: ProtocolDescriptor] = portMap(\.udpPorts)

    private static func portMap(_ kp: KeyPath<ProtocolDescriptor, [UInt16]>) -> [UInt16: ProtocolDescriptor] {
        var m: [UInt16: ProtocolDescriptor] = [:]
        // Generic catalog entries (websocket, rlogin...) must not shadow primary owners of a port.
        let secondary: Set<String> = ["websocket", "webdav", "rlogin", "wol", "grafana"]
        for p in all where !secondary.contains(p.id) {
            for port in p[keyPath: kp] where m[port] == nil { m[port] = p }
        }
        return m
    }

    public static func grouped(matching query: String) -> [ProtocolGroup] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return ProtocolCategory.allCases.compactMap { cat in
            let items = all.filter { p in
                p.category == cat && (q.isEmpty || p.name.lowercased().contains(q) || p.id.contains(q)
                    || p.tcpPorts.contains { String($0) == q } || p.udpPorts.contains { String($0) == q })
            }
            return items.isEmpty ? nil : ProtocolGroup(category: cat, items: items)
        }
    }
}
