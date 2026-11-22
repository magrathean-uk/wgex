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
    name: "WGEXAppComposition",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [
        .library(name: "WGEXAppComposition", targets: ["WGEXAppComposition"]),
    ],
    dependencies: [
        .package(path: "../WGEXCore"),
        .package(path: "../WGEXProfileStore"),
    ],
    targets: [
        .target(
            name: "WGEXAppComposition",
            dependencies: [
                .product(name: "WGEXCore", package: "WGEXCore"),
                .product(name: "WGEXProfileStore", package: "WGEXProfileStore"),
            ],
            swiftSettings: swiftSettings,
        ),
        .testTarget(name: "WGEXAppCompositionTests", dependencies: ["WGEXAppComposition"], swiftSettings: swiftSettings),
    ],
)
