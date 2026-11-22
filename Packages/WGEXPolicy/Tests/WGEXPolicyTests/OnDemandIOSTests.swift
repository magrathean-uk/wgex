// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXPolicy

/// One row per official iOS Cellular and Wi-Fi combination (M06-T01).
private struct IOSRow: Sendable {
    fileprivate let interfaces: OnDemandIOSInterfaces
    fileprivate let rules: [OnDemandRule]
}

private struct OnDemandIOSTests {
    private static let unsorted = ["Z", "A", "Z"]
    private static let connectAny = OnDemandRule(interfaceTypeMatch: .any, action: .connect)
    private static let disconnectAny = OnDemandRule(interfaceTypeMatch: .any, action: .disconnect)
    private static let connectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .connect)
    private static let disconnectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .disconnect)
    private static let connectCellular = OnDemandRule(interfaceTypeMatch: .cellular, action: .connect)
    private static func wifi(_ action: OnDemandRule.Action) -> OnDemandRule {
        OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: ["A", "Z"], action: action)
    }

    private static let table: [IOSRow] = [
        IOSRow(interfaces: .cellularOnly, rules: [connectCellular, disconnectAny]),
        IOSRow(interfaces: .wifiOnly(.anySSID), rules: [connectWifi, disconnectAny]),
        IOSRow(interfaces: .wifiOnly(.onlySSIDs(unsorted)), rules: [wifi(.connect), disconnectAny]),
        IOSRow(interfaces: .wifiOnly(.exceptSSIDs(unsorted)), rules: [wifi(.disconnect), connectWifi, disconnectAny]),
        IOSRow(interfaces: .wifiOrCellular(.anySSID), rules: [connectAny]),
        IOSRow(interfaces: .wifiOrCellular(.onlySSIDs(unsorted)), rules: [wifi(.connect), disconnectWifi, connectAny]),
        IOSRow(interfaces: .wifiOrCellular(.exceptSSIDs(unsorted)), rules: [wifi(.disconnect), connectAny]),
        // An empty list is any SSID; an empty except list must not disconnect on every Wi-Fi network.
        IOSRow(interfaces: .wifiOnly(.onlySSIDs([])), rules: [connectWifi, disconnectAny]),
        IOSRow(interfaces: .wifiOnly(.exceptSSIDs([])), rules: [connectWifi, disconnectAny]),
        IOSRow(interfaces: .wifiOrCellular(.onlySSIDs([])), rules: [connectAny]),
        IOSRow(interfaces: .wifiOrCellular(.exceptSSIDs([])), rules: [connectAny]),
    ]

    @Test(arguments: Self.table)
    func `every iOS combination compiles to first-match rules ending in an any rule`(row: IOSRow) {
        let compilation = OnDemandCompiler.compile(.iosInterfaces(row.interfaces), for: .iOS)
        #expect(compilation.rules == row.rules)
        #expect(compilation.diagnostics.isEmpty)
        #expect(compilation.rules.last?.interfaceTypeMatch == .any)
        #expect(OnDemandCompiler.compile(.iosInterfaces(row.interfaces), for: .iOS) == compilation)
    }

    @Test(arguments: Self.table)
    func `macOS and tvOS emit a diagnostic and no rules`(row: IOSRow) {
        for platform: ProfilePlatform in [.macOS, .tvOS] {
            let compilation = OnDemandCompiler.compile(.iosInterfaces(row.interfaces), for: platform)
            #expect(compilation.rules.isEmpty)
            #expect(compilation.diagnostics == [.iosInterfacesRequiresIOS])
        }
        #expect(OnDemandCompiler.macInterfaces(.iosInterfaces(row.interfaces)) == nil)
    }

    @Test
    func `legacy cases keep their rules and match the equivalent iOS shape`() {
        let pairs: [(OnDemandPolicy, OnDemandIOSInterfaces)] = [
            (.always(exceptSSIDs: []), .wifiOrCellular(.anySSID)),
            (.always(exceptSSIDs: []), .wifiOrCellular(.exceptSSIDs([]))),
            (.wifiOnly(exceptSSIDs: []), .wifiOnly(.exceptSSIDs([]))),
            (.always(exceptSSIDs: Self.unsorted), .wifiOrCellular(.exceptSSIDs(Self.unsorted))),
            (.wifiOnly(exceptSSIDs: []), .wifiOnly(.anySSID)),
            (.wifiOnly(exceptSSIDs: Self.unsorted), .wifiOnly(.exceptSSIDs(Self.unsorted))),
            (.cellularOnly, .cellularOnly),
        ]
        for (legacy, shape) in pairs {
            #expect(OnDemandCompiler.compile(legacy, for: .iOS) == OnDemandCompiler.compile(.iosInterfaces(shape), for: .iOS))
        }
    }

    @Test
    func `the Mac evaluator holds on the empty macOS rule list`() {
        let rules = OnDemandCompiler.compile(.iosInterfaces(.wifiOrCellular(.anySSID)), for: .macOS).rules
        #expect(OnDemandEvaluator.evaluate(rules, context: OnDemandNetworkContext(network: .wifi, ssid: .known("A"))) == .hold(.noRule))
    }
}
