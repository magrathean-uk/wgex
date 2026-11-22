// swift-tools-version: 6.4
// Negative fixture for check-package-deps.sh: the client product links the
// engine, the daemon core imports SwiftUI, and tvOS is missing.
import PackageDescription

private let settings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
]

private let package = Package(
    name: "WGEXBackendMac",
    platforms: [.macOS(.v26), .iOS(.v27)],
    products: [
        .library(name: "WGEXDaemonProtocol", targets: ["WGEXDaemonProtocol"]),
        .library(name: "WGEXDaemonClient", targets: ["WGEXDaemonClient"]),
        .library(name: "WGEXDaemonCore", targets: ["WGEXDaemonCore"]),
    ],
    dependencies: [.package(path: "../WGEXCore"), .package(path: "../WGEXEngine"), .package(path: "../WGEXProfileStore")],
    targets: [
        .target(name: "WGEXDaemonProtocol", dependencies: [.product(name: "WGEXCore", package: "WGEXCore")], swiftSettings: settings),
        .target(
            name: "WGEXDaemonClient",
            dependencies: [
                "WGEXDaemonProtocol",
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
                .product(name: "WGEXEngine", package: "WGEXEngine"),
            ],
            swiftSettings: settings,
        ),
        .target(name: "WGEXDaemonCore", dependencies: ["WGEXDaemonProtocol"], swiftSettings: settings),
    ],
)
