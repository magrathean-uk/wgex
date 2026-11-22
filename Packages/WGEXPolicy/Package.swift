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
    name: "WGEXPolicy",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXPolicy", targets: ["WGEXPolicy"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
    ],
    targets: [
        .target(
            name: "WGEXPolicy",
            dependencies: [.product(name: "WGEXCore", package: "WGEXCore")],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXPolicyTests",
            dependencies: ["WGEXPolicy", .product(name: "WGEXCore", package: "WGEXCore")],
            swiftSettings: swiftSettings,
        ),
    ],
)
