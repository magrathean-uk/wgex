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
    name: "WGEXBackendNE",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXNEClient", targets: ["WGEXNEClient"]),
        .library(name: "WGEXNEProvider", targets: ["WGEXNEProvider"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXPolicy"),
        .package(path: "../WGEXProfileStore"),
        .package(path: "../WGEXEngineInterface"),
    ],
    targets: [
        .target(
            name: "WGEXNEClient",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXPolicy", package: "WGEXPolicy"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
            ],
            swiftSettings: swiftSettings,
            linkerSettings: [.linkedFramework("NetworkExtension")],
        ),
        .target(
            name: "WGEXNEProvider",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXPolicy", package: "WGEXPolicy"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
            ],
            swiftSettings: swiftSettings,
            linkerSettings: [.linkedFramework("NetworkExtension")],
        ),
        .testTarget(
            name: "WGEXNEClientTests",
            dependencies: ["WGEXNEClient", .product(name: "WGEXCore", package: "WGEXCore")],
            resources: [.copy("Goldens")],
            swiftSettings: swiftSettings,
        ),
        .testTarget(
            name: "WGEXNEProviderTests",
            dependencies: [
                "WGEXNEProvider",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
            ],
            resources: [.copy("Goldens")],
            swiftSettings: swiftSettings,
        ),
    ],
)
