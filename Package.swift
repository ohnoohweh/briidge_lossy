// swift-tools-version: 6.0
import PackageDescription

var products: [Product] = [
    .library(name: "ObstacleBridgeCore", targets: ["ObstacleBridgeCore"]),
    .executable(name: "ObstacleBridgeLogCollector", targets: ["ObstacleBridgeLogCollector"]),
    .executable(name: "ObstacleBridgeProxyWorker", targets: ["ObstacleBridgeProxyWorker"]),
]

var targets: [Target] = [
    .target(
        name: "ObstacleBridgeDesktopShared",
        path: "swift/Sources/ObstacleBridgeDesktopShared"
    ),
    .executableTarget(
        name: "ObstacleBridgeProxyWorker",
        dependencies: ["ObstacleBridgeDesktopShared"],
        path: "swift/Sources/ObstacleBridgeProxyWorker"
    ),
    .executableTarget(
        name: "ObstacleBridgeLogCollector",
        dependencies: ["ObstacleBridgeDesktopShared"],
        path: "swift/Sources/ObstacleBridgeLogCollector"
    ),
    .systemLibrary(
        name: "CZlib",
        // The checked-in module map declares the standard zlib header and
        // linker flag. Avoid pkg-config here: some distributions publish the
        // unsupported -DWITH_GZFILEOP C flag, which SwiftPM reports as a
        // build warning despite the flag being unnecessary for this target.
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

var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.0"),
]

#if os(Linux)
packageDependencies += [
    .package(url: "https://github.com/apple/swift-log.git", exact: "1.16.1"),
    .package(url: "https://github.com/apple/swift-nio.git", exact: "2.104.0"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.37.5"),
    // Pin the qualified Linux QUIC backend because its public API evolves
    // independently of this foreground runtime.
    .package(url: "https://github.com/apple/swift-nio-quic.git", exact: "0.4.1"),
]
products.append(.executable(name: "ObstacleBridgeLinux", targets: ["ObstacleBridgeLinux"]))
targets += [
    .target(
        name: "ObstacleBridgeLinuxAdapters",
        dependencies: [
            "ObstacleBridgeCore",
            "ObstacleBridgeDesktopShared",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "Logging", package: "swift-log"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOTLS", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
            .product(name: "NIOQUIC", package: "swift-nio-quic"),
        ],
        path: "swift/Sources/ObstacleBridgeLinux/Adapters"
    ),
    .executableTarget(
        name: "ObstacleBridgeLinux",
        dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgeCore", "ObstacleBridgeDesktopShared"],
        path: "swift/Sources/ObstacleBridgeLinux",
        exclude: ["Adapters"]
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
    dependencies: packageDependencies,
    targets: targets,
    swiftLanguageModes: [.v6]
)
