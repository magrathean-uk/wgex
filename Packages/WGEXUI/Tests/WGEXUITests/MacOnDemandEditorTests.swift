// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

/// The macOS on-demand editor (ADR-030 section 2): the official option set, validation and persistence of the policy.
private struct MacOnDemandEditorTests {
    private func editor(policy: OnDemandPolicy = .off) throws -> ProfileEditorModel {
        var parsed = try EditorFixtures.parsed()
        parsed.profile.onDemand = policy
        return try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
    }

    // MARK: Option set

    @Test(arguments: [
        (OnDemandPolicy.off, false, false, MacOnDemandForm.NetworkMatch.any, [String]()),
        (.interfaces(.ethernetOnly), true, false, .any, []),
        (.interfaces(.wifiOnly(.anySSID)), false, true, .any, []),
        (.interfaces(.wifiOnly(.onlySSIDs(["Home", "Work"]))), false, true, .only, ["Home", "Work"]),
        (.interfaces(.wifiOnly(.exceptSSIDs(["Home"]))), false, true, .except, ["Home"]),
        (.interfaces(.wifiOrEthernet(.anySSID)), true, true, .any, []),
        (.interfaces(.wifiOrEthernet(.onlySSIDs(["Home"]))), true, true, .only, ["Home"]),
        (.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), true, true, .except, ["Home"]),
    ])
    func `every official option reads into the form and writes back unchanged`(
        _ policy: OnDemandPolicy, _ ethernet: Bool, _ wifi: Bool, _ match: MacOnDemandForm.NetworkMatch, _ names: [String],
    ) {
        let form = MacOnDemandForm(policy: policy)
        #expect(form.ethernet == ethernet)
        #expect(form.wifi == wifi)
        #expect(form.match == match)
        #expect(form.networks.map(\.name) == names)
        #expect(form.issues.isEmpty)
        #expect(form.policy == policy)
    }

    @Test
    func `the checkboxes choose the interface case and neither is off`() {
        var form = MacOnDemandForm()
        #expect(!form.isEnabled)
        #expect(form.policy == .off)
        form.ethernet = true
        #expect(form.policy == .interfaces(.ethernetOnly))
        form.wifi = true
        #expect(form.policy == .interfaces(.wifiOrEthernet(.anySSID)))
        form.ethernet = false
        #expect(form.policy == .interfaces(.wifiOnly(.anySSID)))
    }

    @Test
    func `a list belongs to Wi-Fi only so Ethernet only ignores it`() {
        let form = MacOnDemandForm(
            ethernet: true, wifi: false, match: .only, networks: [.init(name: "")],
        )
        #expect(!form.usesList)
        #expect(form.issues.isEmpty)
        #expect(form.policy == .interfaces(.ethernetOnly))
    }

    @Test(arguments: [
        (OnDemandPolicy.always(exceptSSIDs: []), OnDemandPolicy.interfaces(.wifiOrEthernet(.anySSID))),
        (.always(exceptSSIDs: ["Home"]), .interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"])))),
        (.wifiOnly(exceptSSIDs: []), .interfaces(.wifiOnly(.anySSID))),
        (.wifiOnly(exceptSSIDs: ["Home"]), .interfaces(.wifiOnly(.exceptSSIDs(["Home"])))),
        (.cellularOnly, .off),
    ])
    func `legacy iOS shapes normalise as on the daemon`(_ legacy: OnDemandPolicy, _ normalised: OnDemandPolicy) {
        #expect(MacOnDemandForm(policy: legacy).policy == normalised)
    }

    // MARK: Validation

    @Test(arguments: [MacOnDemandForm.NetworkMatch.only, .except])
    func `an include or exclude rule with no network saves as any network and says so`(_ match: MacOnDemandForm.NetworkMatch) {
        let wifi = MacOnDemandForm(ethernet: false, wifi: true, match: match)
        #expect(wifi.issues.isEmpty)
        #expect(wifi.savesAsAnyNetwork)
        #expect(wifi.policy == .interfaces(.wifiOnly(.anySSID)))
        let both = MacOnDemandForm(ethernet: true, wifi: true, match: match)
        #expect(both.savesAsAnyNetwork)
        #expect(both.policy == .interfaces(.wifiOrEthernet(.anySSID)))
        var listed = wifi
        #expect(listed.add("Home") == .added)
        #expect(!listed.savesAsAnyNetwork)
        #expect(MacOnDemandForm(ethernet: false, wifi: true, match: .any).savesAsAnyNetwork == false)
        #expect(MacOnDemandForm(ethernet: true, wifi: false, match: match).savesAsAnyNetwork == false)
    }

    @Test
    func `names are 1 to 32 bytes without control characters or duplicates and at most 64`() {
        func issues(_ names: [String]) -> [MacOnDemandForm.Issue] {
            MacOnDemandForm(ethernet: false, wifi: true, match: .only, networks: names.map { .init(name: $0) }).issues
        }
        #expect(issues(["Home"]).isEmpty)
        #expect(issues([String(repeating: "a", count: 32)]).isEmpty)
        #expect(issues([String(repeating: "a", count: 33)]) == [.nameLength])
        #expect(issues(["é" + String(repeating: "a", count: 31)]) == [.nameLength])
        #expect(issues([""]) == [.nameLength])
        #expect(issues(["Ho\u{0}me"]) == [.nameControl])
        #expect(issues(["Ho\nme"]) == [.nameControl])
        #expect(issues(["Home", "Home"]) == [.duplicate])
        #expect(issues(["Home", "home"]).isEmpty)
        #expect(issues((0 ..< 64).map { "n\($0)" }).isEmpty)
        #expect(issues((0 ..< 65).map { "n\($0)" }) == [.listLimit])
    }

    @Test
    func `adding stops at duplicates and at the list bound`() {
        var form = MacOnDemandForm(ethernet: false, wifi: true, match: .only)
        #expect(form.add("Home") == .added)
        #expect(form.add("Home") == .alreadyListed)
        for index in 0 ..< 63 {
            #expect(form.add("n\(index)") == .added)
        }
        #expect(form.add("extra") == .listFull)
        form.addBlankRow()
        #expect(form.networks.count == MacOnDemandForm.maximumNetworks)
    }

    // MARK: Model integration and persistence

    @Test
    func `editing the form changes the saved policy and marks the draft dirty`() throws {
        let model = try editor()
        #expect(!model.isDirty)
        model.draft.onDemandForm.wifi = true
        model.draft.onDemandForm.match = .except
        #expect(model.draft.onDemandForm.add("Home") == .added)
        #expect(model.isDirty)
        #expect(model.canSave)
        let saved = try model.validatedProfile()
        #expect(saved.onDemand == .interfaces(.wifiOnly(.exceptSSIDs(["Home"]))))
    }

    @Test
    func `an empty include list saves as any network`() throws {
        let model = try editor()
        model.draft.onDemandForm.wifi = true
        model.draft.onDemandForm.match = .only
        #expect(model.draft.onDemandForm.savesAsAnyNetwork)
        #expect(model.canSave)
        #expect(model.diagnostics(for: .onDemand).isEmpty)
        #expect(try model.validatedProfile().onDemand == .interfaces(.wifiOnly(.anySSID)))
    }

    @Test
    func `an invalid list blocks save and the badge names the on-demand field`() throws {
        let model = try editor()
        model.draft.onDemandForm.wifi = true
        model.draft.onDemandForm.match = .only
        model.draft.onDemandForm.addBlankRow()
        #expect(!model.canSave)
        #expect(throws: (any Error).self) { _ = try model.validatedProfile() }
        #expect(model.diagnostics(for: .onDemand).map(\.message) == [MacStrings.onDemandNameLength])
        model.draft.onDemandForm.networks[0].name = "Home"
        #expect(model.canSave)
        #expect(model.diagnostics(for: .onDemand).isEmpty)
    }

    @Test
    func `opening and saving without touching on-demand keeps a legacy policy as stored`() throws {
        let model = try editor(policy: .always(exceptSSIDs: ["Home"]))
        model.draft.name = "Renamed"
        let saved = try model.validatedProfile()
        #expect(saved.onDemand == .always(exceptSSIDs: ["Home"]))
    }

    @Test
    func `reverting an on-demand edit leaves the draft clean again`() throws {
        let model = try editor(policy: .interfaces(.ethernetOnly))
        model.draft.onDemandForm.wifi = true
        #expect(model.isDirty)
        model.draft.onDemandForm.wifi = false
        #expect(!model.isDirty)
        #expect(try model.validatedProfile().onDemand == .interfaces(.ethernetOnly))
    }

    @Test
    func `the saved policy survives a document round trip`() throws {
        let model = try editor()
        model.draft.onDemandForm = MacOnDemandForm(policy: .interfaces(.wifiOrEthernet(.onlySSIDs(["Café", "Home"]))))
        let saved = try model.validatedProfile()
        let decoded = try JSONDecoder().decode(TunnelProfile.self, from: JSONEncoder().encode(saved))
        #expect(decoded.onDemand == .interfaces(.wifiOrEthernet(.onlySSIDs(["Café", "Home"]))))
        #expect(MacOnDemandForm(policy: decoded.onDemand) == model.draft.onDemandForm)
    }
}
