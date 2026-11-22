// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import PackageDescription

private let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .treatAllWarnings(as: .error),
]

private let package = Package(
    name: "WGEXPairing",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXPairing", targets: ["WGEXPairing"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
    ],
    targets: [
        .target(
            name: "WGEXPairing",
            dependencies: [.product(name: "WGEXCore", package: "WGEXCore")],
            swiftSettings: swiftSettings,
        ),
        .testTarget(name: "WGEXPairingTests", dependencies: ["WGEXPairing"], swiftSettings: swiftSettings),
    ],
)
