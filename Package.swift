// swift-tools-version: 6.0
import PackageDescription

var products: [Product] = [
    .library(name: "ObstacleBridgeCore", targets: ["ObstacleBridgeCore"]),
]

var targets: [Target] = [
    .target(
        name: "ObstacleBridgeCore",
        dependencies: [
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
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ],
    targets: targets,
    swiftLanguageModes: [.v6]
)
