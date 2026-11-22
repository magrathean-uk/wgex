// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXPolicy

private struct MacRow: Sendable, CustomTestStringConvertible {
    fileprivate let interfaces: OnDemandInterfaces
    fileprivate let rules: [OnDemandRule]
    fileprivate var testDescription: String {
        String(describing: interfaces)
    }
}

/// ADR-030 section 2: every macOS row, legacy normalisation, the iOS and tvOS outputs and the evaluator matrix.
private struct OnDemandMacTests {
    private static let connectAny = OnDemandRule(interfaceTypeMatch: .any, action: .connect)
    private static let disconnectAny = OnDemandRule(interfaceTypeMatch: .any, action: .disconnect)
    private static let connectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .connect)
    private static let disconnectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .disconnect)
    private static let listed = ["A", "Z"]
    private static func wifi(_ action: OnDemandRule.Action) -> OnDemandRule {
        OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: listed, action: action)
    }

    private static let unsorted = ["Z", "A", "Z"]

    private static let rows: [MacRow] = [
        MacRow(interfaces: .ethernetOnly, rules: [disconnectWifi, connectAny]),
        MacRow(interfaces: .wifiOnly(.anySSID), rules: [connectWifi, disconnectAny]),
        MacRow(interfaces: .wifiOnly(.onlySSIDs(unsorted)), rules: [wifi(.connect), disconnectAny]),
        MacRow(interfaces: .wifiOnly(.exceptSSIDs(unsorted)), rules: [wifi(.disconnect), connectWifi, disconnectAny]),
        MacRow(interfaces: .wifiOrEthernet(.anySSID), rules: [connectAny]),
        MacRow(interfaces: .wifiOrEthernet(.onlySSIDs(unsorted)), rules: [wifi(.connect), disconnectWifi, connectAny]),
        MacRow(interfaces: .wifiOrEthernet(.exceptSSIDs(unsorted)), rules: [wifi(.disconnect), connectAny]),
    ]

    @Test(arguments: Self.rows)
    func `each macOS row compiles to the ADR table and ends in an any rule`(row: MacRow) {
        let compilation = OnDemandCompiler.compile(.interfaces(row.interfaces), for: .macOS)
        #expect(compilation.rules == row.rules)
        #expect(compilation.diagnostics.isEmpty)
        #expect(compilation.rules.last?.interfaceTypeMatch == .any)
        #expect(!compilation.rules.contains { $0.interfaceTypeMatch == .cellular })
    }

    @Test(arguments: Self.rows)
    func `interfaces emit no rules on iOS and tvOS`(row: MacRow) {
        for platform: ProfilePlatform in [.iOS, .tvOS] {
            let compilation = OnDemandCompiler.compile(.interfaces(row.interfaces), for: platform)
            #expect(compilation.rules.isEmpty)
            #expect(compilation.diagnostics == [.interfacesRequiresMacOS])
        }
    }

    @Test
    func `legacy cases normalise to the macOS option set`() {
        #expect(OnDemandCompiler.macInterfaces(.always(exceptSSIDs: [])) == .wifiOrEthernet(.anySSID))
        #expect(OnDemandCompiler.macInterfaces(.always(exceptSSIDs: ["A"])) == .wifiOrEthernet(.exceptSSIDs(["A"])))
        #expect(OnDemandCompiler.macInterfaces(.wifiOnly(exceptSSIDs: [])) == .wifiOnly(.anySSID))
        #expect(OnDemandCompiler.macInterfaces(.wifiOnly(exceptSSIDs: ["A"])) == .wifiOnly(.exceptSSIDs(["A"])))
        #expect(OnDemandCompiler.macInterfaces(.cellularOnly) == nil)
        #expect(OnDemandCompiler.macInterfaces(.off) == nil)
        for legacy: OnDemandPolicy in [.always(exceptSSIDs: Self.unsorted), .wifiOnly(exceptSSIDs: []), .always(exceptSSIDs: [])] {
            let normalised = OnDemandCompiler.macInterfaces(legacy).map(OnDemandPolicy.interfaces)
            #expect(normalised.map { OnDemandCompiler.compile($0, for: .macOS) } == OnDemandCompiler.compile(legacy, for: .macOS))
        }
        let cellular = OnDemandCompiler.compile(.cellularOnly, for: .macOS)
        #expect(cellular.rules.isEmpty && cellular.diagnostics == [.cellularRequiresIOS])
    }

    private typealias Context = OnDemandNetworkContext

    /// Expected decision per row on: ethernet, wifi listed, wifi unlisted, wifi unknown, none.
    private static let matrix: [(OnDemandInterfaces, [OnDemandEvaluator.Decision])] = [
        (.ethernetOnly, [.connect, .disconnect, .disconnect, .disconnect, .hold(.noNetwork)]),
        (.wifiOnly(.anySSID), [.disconnect, .connect, .connect, .connect, .hold(.noNetwork)]),
        (.wifiOnly(.onlySSIDs(listed)), [.disconnect, .connect, .disconnect, .hold(.ssidUnavailable), .hold(.noNetwork)]),
        (.wifiOnly(.exceptSSIDs(listed)), [.disconnect, .disconnect, .connect, .connect, .hold(.noNetwork)]),
        (.wifiOrEthernet(.anySSID), [.connect, .connect, .connect, .connect, .hold(.noNetwork)]),
        (.wifiOrEthernet(.onlySSIDs(listed)), [.connect, .connect, .disconnect, .hold(.ssidUnavailable), .hold(.noNetwork)]),
        (.wifiOrEthernet(.exceptSSIDs(listed)), [.connect, .disconnect, .connect, .connect, .hold(.noNetwork)]),
    ]

    @Test
    func `evaluator matrix over network class, SSID state and policy`() {
        let contexts: [Context] = [
            Context(network: .ethernet), Context(network: .wifi, ssid: .known("A")), Context(network: .wifi, ssid: .known("B")),
            Context(network: .wifi, ssid: .unknown), Context(network: .none),
        ]
        for (interfaces, expected) in Self.matrix {
            let rules = OnDemandCompiler.compile(.interfaces(interfaces), for: .macOS).rules
            for (context, decision) in zip(contexts, expected) {
                #expect(OnDemandEvaluator.evaluate(rules, context: context) == decision, "\(interfaces) \(context)")
            }
        }
    }

    @Test
    func `SSIDs match by exact case-sensitive equality`() {
        let rules = OnDemandCompiler.compile(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), for: .macOS).rules
        #expect(OnDemandEvaluator.evaluate(rules, context: Context(network: .wifi, ssid: .known("home"))) == .disconnect)
        #expect(OnDemandEvaluator.evaluate(rules, context: Context(network: .wifi, ssid: .known("Home"))) == .connect)
    }
}
