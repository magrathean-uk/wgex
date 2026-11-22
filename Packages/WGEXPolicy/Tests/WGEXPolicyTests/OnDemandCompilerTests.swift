// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXPolicy

private struct OnDemandGolden: Sendable {
    fileprivate let policy: OnDemandPolicy
    fileprivate let platform: ProfilePlatform
    fileprivate let rules: [OnDemandRule]
    fileprivate let diagnostics: [OnDemandCompilation.Diagnostic]
}

private struct OnDemandCompilerTests {
    private static let connectAny = OnDemandRule(interfaceTypeMatch: .any, action: .connect)
    private static let disconnectAny = OnDemandRule(interfaceTypeMatch: .any, action: .disconnect)
    private static let connectWifi = OnDemandRule(interfaceTypeMatch: .wifi, action: .connect)
    private static let disconnectTrusted = OnDemandRule(interfaceTypeMatch: .wifi, ssidMatch: ["A", "Z"], action: .disconnect)
    private static let policies: [OnDemandPolicy] = [
        .off, .always(exceptSSIDs: []), .always(exceptSSIDs: ["Z", "A", "Z"]),
        .wifiOnly(exceptSSIDs: []), .wifiOnly(exceptSSIDs: ["Z", "A", "Z"]), .cellularOnly,
    ]

    private static var goldens: [OnDemandGolden] {
        let iosRules: [[OnDemandRule]] = [
            [], [connectAny], [disconnectTrusted, connectAny], [connectWifi, disconnectAny], [
                disconnectTrusted,
                connectWifi,
                disconnectAny,
            ],
            [OnDemandRule(interfaceTypeMatch: .cellular, action: .connect), disconnectAny],
        ]
        // Legacy cases normalise on macOS: always -> wifiOrEthernet, wifiOnly -> wifiOnly (ADR-030 section 2).
        let macRules: [[OnDemandRule]] = [
            [], [connectAny], [disconnectTrusted, connectAny], [connectWifi, disconnectAny],
            [disconnectTrusted, connectWifi, disconnectAny], [],
        ]
        var cases: [OnDemandGolden] = []
        for (index, policy) in policies.enumerated() {
            cases.append(OnDemandGolden(policy: policy, platform: .iOS, rules: iosRules[index], diagnostics: []))
            cases.append(OnDemandGolden(
                policy: policy, platform: .macOS, rules: macRules[index], diagnostics: index == 5 ? [.cellularRequiresIOS] : [],
            ))
            let tvRules: [OnDemandRule] = index == 0 || index == 5 ? [] : [connectAny]
            let tvDiagnostics: [OnDemandCompilation.Diagnostic] = index == 0 ? []
                : (index == 5 ? [.cellularRequiresIOS] : [.tvOSUsesAnyInterface])
            cases.append(OnDemandGolden(policy: policy, platform: .tvOS, rules: tvRules, diagnostics: tvDiagnostics))
        }
        return cases
    }

    @Test(arguments: Self.goldens)
    func `golden rules per policy and platform are ordered and deterministic`(golden: OnDemandGolden) {
        let compilation = OnDemandCompiler.compile(golden.policy, for: golden.platform)
        #expect(compilation.rules == golden.rules)
        #expect(compilation.diagnostics == golden.diagnostics)
        #expect(OnDemandCompiler.compile(golden.policy, for: golden.platform) == compilation)
        if case .tvOS = golden.platform {
            #expect(compilation.rules.allSatisfy { $0.interfaceTypeMatch == .any && $0.ssidMatch.isEmpty })
        }
        if compilation.rules.contains(where: { $0.interfaceTypeMatch == .cellular }) {
            if case .iOS = golden.platform {} else {
                Issue.record("Cellular rule outside iOS")
            }
        }
    }

    @Test
    func `default mobile policy compiles to any interface`() {
        for platform: ProfilePlatform in [.iOS, .tvOS] {
            #expect(OnDemandCompiler.compile(.defaults(for: platform), for: platform).rules == [Self.connectAny])
        }
    }
}
