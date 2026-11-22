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
    name: "WGEXUITesting",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXUITesting", targets: ["WGEXUITesting"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXUI"),
        .package(path: "../WGEXTesting"),
    ],
    targets: [
        .target(
            name: "WGEXUITesting",
            dependencies: [
                .product(name: "WGEXUI", package: "WGEXUI"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
                .product(name: "WGEXCore", package: "WGEXCore"),
            ],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXUITestingTests",
            dependencies: [
                "WGEXUITesting",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
            ],
            swiftSettings: swiftSettings,
        ),
    ],
)
