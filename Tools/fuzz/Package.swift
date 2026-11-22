// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import PackageDescription

private let package = Package(
    name: "WGEXSwiftFuzz",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    dependencies: [
        .package(path: "../../Packages/WGEXCore"),
        .package(path: "../../Packages/WGEXProfileStore"),
        .package(path: "../../Packages/WGEXPairing"),
        .package(path: "../../Packages/WGEXDiagnostics"),
        .package(path: "../../Packages/WGEXTesting"),
    ],
    targets: [
        .executableTarget(
            name: "swift-fuzz",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXPairing", package: "WGEXPairing"),
                .product(name: "WGEXDiagnostics", package: "WGEXDiagnostics"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
            ],
            path: "Sources/SwiftFuzz",
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
                .enableUpcomingFeature("InferIsolatedConformances"),
                .enableUpcomingFeature("MemberImportVisibility"),
                .enableUpcomingFeature("ExistentialAny"),
                .treatAllWarnings(as: .error),
            ],
        ),
    ],
)
