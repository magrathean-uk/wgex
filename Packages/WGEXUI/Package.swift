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
    .defaultIsolation(MainActor.self),
]

private let package = Package(
    name: "WGEXUI",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXUI", targets: ["WGEXUI"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXPolicy"),
        .package(path: "../WGEXTesting"),
        .package(path: "../WGEXProfileStore"),
        .package(path: "../WGEXAppComposition"),
        .package(path: "../WGEXBackendMac"),
        .package(path: "../WGEXEngineInterface"),
    ],
    targets: [
        .target(
            name: "WGEXUI",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXPolicy", package: "WGEXPolicy"),
            ],
            resources: [.process("Resources")],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXUITests",
            dependencies: [
                "WGEXUI",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXAppComposition", package: "WGEXAppComposition"),
                .product(name: "WGEXDaemonClient", package: "WGEXBackendMac", condition: .when(platforms: [.macOS])),
                .product(name: "WGEXDaemonProtocol", package: "WGEXBackendMac", condition: .when(platforms: [.macOS])),
                .product(name: "WGEXDaemonCore", package: "WGEXBackendMac", condition: .when(platforms: [.macOS])),
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface", condition: .when(platforms: [.macOS])),
            ],
            swiftSettings: swiftSettings,
        ),
    ],
)
