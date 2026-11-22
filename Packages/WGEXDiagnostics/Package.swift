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
    name: "WGEXDiagnostics",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXDiagnostics", targets: ["WGEXDiagnostics"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXBackendMac"),
        .package(path: "../WGEXTesting"),
    ],
    targets: [
        .target(
            name: "WGEXDiagnostics",
            dependencies: [.product(name: "WGEXCore", package: "WGEXCore")],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXDiagnosticsTests",
            dependencies: [
                "WGEXDiagnostics",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXDaemonCore", package: "WGEXBackendMac"),
                .product(name: "WGEXDaemonCoreTesting", package: "WGEXBackendMac"),
                .product(name: "WGEXDaemonProtocol", package: "WGEXBackendMac"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
            ],
            swiftSettings: swiftSettings,
        ),
    ],
)
