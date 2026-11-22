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
    name: "WGEXTesting",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXTesting", targets: ["WGEXTesting"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXPolicy"),
        .package(path: "../WGEXEngineInterface"),
    ],
    targets: [
        .target(
            name: "WGEXTesting",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXPolicy", package: "WGEXPolicy"),
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
            ],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXTestingTests",
            dependencies: [
                "WGEXTesting",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
            ],
            swiftSettings: swiftSettings,
        ),
    ],
)
