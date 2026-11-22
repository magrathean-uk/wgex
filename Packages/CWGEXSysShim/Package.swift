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
    name: "CWGEXSysShim",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "CWGEXSysShim", targets: ["CWGEXSysShim"]),
    ],
    targets: [
        .target(name: "CWGEXSysShim"),
        .testTarget(name: "CWGEXSysShimTests", dependencies: ["CWGEXSysShim"], swiftSettings: swiftSettings),
    ],
)
