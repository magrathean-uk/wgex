// SPDX-License-Identifier: MIT

// swift-tools-version: 6.4
import PackageDescription

private let settings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ExistentialAny"),
    .treatAllWarnings(as: .error),
]

private let package = Package(
    name: "LeakProbe",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [.library(name: "LeakProbe", targets: ["LeakProbe"]), .executable(name: "leakprobe", targets: ["LeakProbeCLI"])],
    targets: [
        .target(name: "LeakProbe", swiftSettings: settings),
        .executableTarget(name: "LeakProbeCLI", dependencies: ["LeakProbe"], swiftSettings: settings),
        .testTarget(name: "LeakProbeTests", dependencies: ["LeakProbe"], swiftSettings: settings),
    ],
)
