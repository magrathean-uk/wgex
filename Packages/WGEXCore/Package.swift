// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import Foundation
import PackageDescription

/// The pre-build step (Config/Scripts/generate-build-identifiers.sh) writes the
/// generated identifiers file; when it exists the checked-in fallback is
/// compiled out (Sources/WGEXCore/Identifiers/BuildIdentifierSource.fallback.swift).
private let generatedIdentifiers = FileManager.default.fileExists(
    atPath: Context.packageDirectory + "/Sources/WGEXCore/Generated/BuildIdentifiers.generated.swift",
)

private let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .treatAllWarnings(as: .error),
]

private let package = Package(
    name: "WGEXCore",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXCore", targets: ["WGEXCore"]),
    ],
    targets: [
        .target(
            name: "WGEXCore",
            exclude: ["Generated/.gitignore"],
            swiftSettings: swiftSettings + (generatedIdentifiers ? [.define("WGEX_GENERATED_IDENTIFIERS")] : []),
        ),
        .testTarget(name: "WGEXCoreTests", dependencies: ["WGEXCore"], exclude: ["Golden"], swiftSettings: swiftSettings),
    ],
)
