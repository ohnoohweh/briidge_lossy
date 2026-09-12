// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ObstacleBridgeLinux",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "ObstacleBridgeCore", targets: ["ObstacleBridgeCore"]),
        .executable(name: "ObstacleBridgeLinux", targets: ["ObstacleBridgeLinux"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ],
    targets: [
        .target(
            name: "ObstacleBridgeCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "swift/Sources/ObstacleBridgeCore"
        ),
        .target(
            name: "ObstacleBridgeLinuxAdapters",
            dependencies: [
                "ObstacleBridgeCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "swift/Sources/ObstacleBridgeLinuxAdapters"
        ),
        .target(
            name: "ObstacleBridgeApplePackageProbe",
            dependencies: ["ObstacleBridgeCore"],
            path: "swift/Probes/ObstacleBridgeApplePackageProbe"
        ),
        .executableTarget(
            name: "ObstacleBridgeLinux",
            dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgeCore"],
            path: "swift/Sources/ObstacleBridgeLinux"
        ),
        .testTarget(
            name: "ObstacleBridgeCoreTests",
            dependencies: ["ObstacleBridgeCore"],
            path: "swift/Tests/ObstacleBridgeCoreTests"
        ),
        .testTarget(
            name: "ObstacleBridgeLinuxAdapterTests",
            dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgeCore"],
            path: "swift/Tests/ObstacleBridgeLinuxAdapterTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
