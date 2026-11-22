// swift-tools-version: 6.4
// Negative fixture for check-package-deps.sh: an edge outside the table
// (WGEXPolicy -> WGEXUI) and MainActor default isolation in a core package.
import PackageDescription

private let package = Package(
    name: "WGEXPolicy",
    platforms: [.macOS(.v26), .iOS(.v27), .tvOS(.v27)],
    products: [.library(name: "WGEXPolicy", targets: ["WGEXPolicy"])],
    dependencies: [.package(path: "../WGEXCore"), .package(path: "../WGEXUI")],
    targets: [
        .target(
            name: "WGEXPolicy",
            dependencies: [.product(name: "WGEXCore", package: "WGEXCore"), .product(name: "WGEXUI", package: "WGEXUI")],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
                .enableUpcomingFeature("InferIsolatedConformances"),
                .enableUpcomingFeature("MemberImportVisibility"),
                .enableUpcomingFeature("ExistentialAny"),
                .defaultIsolation(MainActor.self),
            ],
        ),
    ],
)
