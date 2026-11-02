// swift-tools-version:5.9
import PackageDescription

var products: [Product] = [.library(name: "PacketCore", targets: ["PacketCore"])]
var targets: [Target] = [
    // libpcap ships with the macOS SDK (and libpcap-dev on Linux for CI of the core).
    .systemLibrary(name: "CPcap", path: "Sources/CPcap"),
    .target(name: "PacketCore", dependencies: ["CPcap"], path: "Sources/PacketCore"),
    .testTarget(name: "PacketCoreTests", dependencies: ["PacketCore"], path: "Tests/PacketCoreTests"),
]

#if os(macOS)
// SwiftUI/AppKit front-end — macOS only; the core also builds on Linux for CI.
products.append(.executable(name: "LANA", targets: ["LANA"]))
targets.append(.executableTarget(name: "LANA", dependencies: ["PacketCore"], path: "Sources/LANA"))
#endif

let package = Package(
    name: "LANA",
    platforms: [.macOS(.v14)],
    products: products,
    targets: targets
)
