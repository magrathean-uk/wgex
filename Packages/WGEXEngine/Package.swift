// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import Foundation
import PackageDescription

// Production targets use the five-slice engine. There is no stub product (removed 26 October 2026); tests use FakeEngine from WGEXTesting.

// A Go c-archive carries a whole runtime. SwiftPM must select exactly one archive,
// also avoiding its duplicate libwgex.a/header output paths. Production is the default.
private let testSupport = ProcessInfo.processInfo.environment["WGEX_ENGINE_TEST_SUPPORT"] == "1"
private let engineBinary = testSupport ? "WGEXEngineTestBinary" : "WGEXEngineBinary"

private let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .treatAllWarnings(as: .error),
    .strictMemorySafety(),
] + (testSupport ? [.define("WGEX_ENGINE_TEST_SUPPORT")] : [])

private let package = Package(
    name: "WGEXEngine",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXEngine", targets: ["WGEXEngine"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXEngineInterface"),
    ],
    targets: [
        .target(
            name: "WGEXEngine",
            dependencies: [
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
                .product(name: "WGEXCore", package: "WGEXCore"),
                .byName(name: engineBinary),
            ],
            swiftSettings: swiftSettings,
            linkerSettings: [.linkedFramework("CoreFoundation", .when(platforms: [.iOS, .tvOS]))],
        ),
        .testTarget(
            name: "WGEXEngineTests",
            dependencies: [
                "WGEXEngine",
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
                .product(name: "WGEXCore", package: "WGEXCore"),
            ],
            swiftSettings: swiftSettings,
            linkerSettings: [.linkedFramework("Security", .when(platforms: [.macOS]))],
        ),
    ] + [testSupport
        ? .binaryTarget(name: "WGEXEngineTestBinary", path: "Binary/WGEXEngineTest.xcframework")
        : .binaryTarget(name: "WGEXEngineBinary", path: "Binary/WGEXEngine.xcframework")],
)
