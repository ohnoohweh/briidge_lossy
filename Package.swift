// swift-tools-version: 6.0
import PackageDescription

var products: [Product] = [
    .library(name: "ObstacleBridgeCore", targets: ["ObstacleBridgeCore"]),
]

var targets: [Target] = [
    .systemLibrary(
        name: "CZlib",
        pkgConfig: "zlib",
        providers: [.apt(["zlib1g-dev"]), .brew(["zlib"])]
    ),
    .target(
        name: "ObstacleBridgeCore",
        dependencies: [
            "CZlib",
            .product(name: "Crypto", package: "swift-crypto"),
        ],
        path: "swift/Sources/ObstacleBridgeCore"
    ),
    .target(
        name: "ObstacleBridgeApplePackageProbe",
        dependencies: ["ObstacleBridgeCore"],
        path: "swift/Probes/ObstacleBridgeApplePackageProbe"
    ),
    .testTarget(
        name: "ObstacleBridgeCoreTests",
        dependencies: ["ObstacleBridgeCore"],
        path: "swift/Tests/ObstacleBridgeCoreTests",
        resources: [.process("Fixtures")]
    ),
    .testTarget(
        name: "ObstacleBridgeApplePackageProbeTests",
        dependencies: ["ObstacleBridgeApplePackageProbe"],
        path: "swift/Tests/ObstacleBridgeApplePackageProbeTests"
    ),
]

#if os(Linux)
products.append(.executable(name: "ObstacleBridgeLinux", targets: ["ObstacleBridgeLinux"]))
targets += [
    .target(
        name: "ObstacleBridgeLinuxAdapters",
        dependencies: [
            "ObstacleBridgeCore",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "Logging", package: "swift-log"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOTLS", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
            .product(name: "NIOQUIC", package: "swift-nio-quic"),
        ],
        path: "swift/Sources/ObstacleBridgeLinuxAdapters"
    ),
    .executableTarget(
        name: "ObstacleBridgeLinux",
        dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgeCore"],
        path: "swift/Sources/ObstacleBridgeLinux"
    ),
    .testTarget(
        name: "ObstacleBridgeLinuxAdapterTests",
        dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgeCore"],
        path: "swift/Tests/ObstacleBridgeLinuxAdapterTests"
    ),
]
#endif

let package = Package(
    name: "ObstacleBridgeLinux",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: products,
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", exact: "1.16.1"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.104.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.5"),
        // Pin the qualified Linux QUIC backend because its public API evolves
        // independently of this foreground runtime.
        .package(url: "https://github.com/apple/swift-nio-quic.git", exact: "0.4.1"),
    ],
    targets: targets,
    swiftLanguageModes: [.v6]
)
