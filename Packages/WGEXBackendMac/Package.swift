// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import Foundation
import PackageDescription

/// `WGEX_LAB_BUILD` is compiled in only for the Lab configuration built by
/// `just lab build` (P0-12), which sets WGEX_LAB_BUILD=1 in the build
/// environment. It is one of the three conditions of `LabGuard.isLabHost()`;
/// the other two are checked at runtime and cannot be supplied by environment.
private let labBuild = Context.environment["WGEX_LAB_BUILD"] == "1"

/// Opt in only for an own-Mac Release signed with the designated development identity.
private let ownMacBuild = Context.environment["WGEX_OWN_MAC_BUILD"] == "1"
/// The own-Mac team and leaf are generated, never checked in (Config/Scripts/build-own-mac.sh).
private let ownMacIdentityPath = Context.packageDirectory + "/Sources/WGEXDaemonProtocol/Generated/OwnMacIdentity.generated.swift"
if ownMacBuild, !FileManager.default.fileExists(atPath: ownMacIdentityPath) {
    fatalError("WGEX_OWN_MAC_BUILD needs Generated/OwnMacIdentity.generated.swift; run just build-own-mac")
}

private let variantSettings: [SwiftSetting] = (labBuild ? [.define("WGEX_LAB_BUILD")] : [])
    + (ownMacBuild ? [.define("WGEX_OWN_MAC_BUILD")] : [])

private let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .treatAllWarnings(as: .error),
]

private let package = Package(
    name: "WGEXBackendMac",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXDaemonProtocol", targets: ["WGEXDaemonProtocol"]),
        .library(name: "WGEXDaemonClient", targets: ["WGEXDaemonClient"]),
        .library(name: "WGEXDaemonCore", targets: ["WGEXDaemonCore"]),
        .library(name: "WGEXDaemonCoreTesting", targets: ["WGEXDaemonCoreTesting"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXProfileStore"),
        .package(path: "../WGEXPolicy"),
        .package(path: "../WGEXEngineInterface"),
        .package(path: "../CWGEXSysShim"),
        // The production factory is compiled into the host tests with an injected constructor.
        .package(path: "../WGEXEngine"),
        .package(path: "../WGEXTesting"),
        .package(path: "../WGEXDiagnostics"),
    ],
    targets: [
        .target(
            name: "WGEXDaemonProtocol",
            dependencies: [.product(name: "WGEXCore", package: "WGEXCore")],
            exclude: ["Generated/.gitignore"],
            swiftSettings: swiftSettings + variantSettings,
        ),
        .target(
            name: "WGEXDaemonClient",
            dependencies: [
                "WGEXDaemonProtocol",
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXCore", package: "WGEXCore"),
            ],
            swiftSettings: swiftSettings + variantSettings,
        ),
        .target(
            name: "WGEXDaemonCore",
            dependencies: [
                "WGEXDaemonProtocol",
                .product(name: "WGEXEngineInterface", package: "WGEXEngineInterface"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXPolicy", package: "WGEXPolicy"),
                .product(name: "CWGEXSysShim", package: "CWGEXSysShim"),
                .product(name: "WGEXCore", package: "WGEXCore"),
            ],
            swiftSettings: swiftSettings + variantSettings,
            linkerSettings: [.linkedFramework("SystemConfiguration", .when(platforms: [.macOS]))],
        ),
        .target(
            name: "WGEXDaemonCoreTesting",
            dependencies: [
                "WGEXDaemonCore", "WGEXDaemonProtocol",
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
            ],
            swiftSettings: swiftSettings + variantSettings,
        ),
        .testTarget(
            name: "WGEXDaemonProtocolTests",
            dependencies: ["WGEXDaemonProtocol", .product(name: "WGEXCore", package: "WGEXCore")],
            swiftSettings: swiftSettings + variantSettings,
        ),
        .testTarget(
            name: "WGEXDaemonClientTests",
            dependencies: [
                "WGEXDaemonClient", "WGEXDaemonProtocol", .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
            ],
            swiftSettings: swiftSettings + variantSettings,
        ),
        .testTarget(
            name: "WGEXDaemonCoreTests",
            dependencies: [
                "WGEXDaemonCore", "WGEXDaemonCoreTesting", "WGEXDaemonProtocol",
                // A real client and CLI against the daemon composition (M03-T01 review: the first observation of a cold CLI).
                "WGEXDaemonClient",
                .product(name: "WGEXEngine", package: "WGEXEngine"),
                .product(name: "WGEXTesting", package: "WGEXTesting"),
                .product(name: "WGEXDiagnostics", package: "WGEXDiagnostics"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
            ],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings + variantSettings,
        ),
    ],
)
