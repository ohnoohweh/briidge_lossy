// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ObstacleBridgeLinux",
    products: [
        .executable(name: "ObstacleBridgeLinux", targets: ["ObstacleBridgeLinux"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ],
    targets: [
        .target(
            name: "ObstacleBridgePortable",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "swift/Sources/ObstacleBridgePortable"
        ),
        .target(
            name: "ObstacleBridgeLinuxAdapters",
            dependencies: [
                "ObstacleBridgePortable",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "swift/Sources/ObstacleBridgeLinuxAdapters"
        ),
        .executableTarget(
            name: "ObstacleBridgeLinux",
            dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgePortable"],
            path: "swift/Sources/ObstacleBridgeLinux"
        ),
        .testTarget(
            name: "ObstacleBridgePortableTests",
            dependencies: ["ObstacleBridgePortable"],
            path: "swift/Tests/ObstacleBridgePortableTests"
        ),
        .testTarget(
            name: "ObstacleBridgeLinuxAdapterTests",
            dependencies: ["ObstacleBridgeLinuxAdapters", "ObstacleBridgePortable"],
            path: "swift/Tests/ObstacleBridgeLinuxAdapterTests"
        ),
    ]
)
