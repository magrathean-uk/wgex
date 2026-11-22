// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

/// The iOS on-demand editor (M06-T06): the official Cellular and Wi-Fi option set, its SSID list, the saved policy and the
/// tunnel detail's summary.
private struct IOSOnDemandEditorTests {
    private typealias Match = IOSOnDemandForm.NetworkMatch

    private func editor(policy: OnDemandPolicy) throws -> ProfileEditorModel {
        var parsed = try EditorFixtures.parsed()
        parsed.profile.onDemand = policy
        return try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
    }

    private static let lists: [[String]] = [[], ["Home", "Cafe"]]

    /// The policy every combination must write, derived independently of the form.
    private static func expected(cellular: Bool, wifi: Bool, match: Match, names: [String]) -> OnDemandPolicy {
        if !cellular, !wifi {
            return .off
        }
        if !wifi {
            return .iosInterfaces(.cellularOnly)
        }
        let ssids: OnDemandSSIDMatch = if names.isEmpty || match == .any {
            .anySSID
        } else if match == .only {
            .onlySSIDs(names)
        } else {
            .exceptSSIDs(names)
        }
        return .iosInterfaces(cellular ? .wifiOrCellular(ssids) : .wifiOnly(ssids))
    }

    @Test(arguments: [false, true], [false, true])
    func `every toggle, match and list combination writes the official policy`(_ cellular: Bool, _ wifi: Bool) throws {
        for match in Match.allCases {
            for names in Self.lists {
                let form = IOSOnDemandForm(cellular: cellular, wifi: wifi, match: match, networks: names.map { .init(name: $0) })
                let policy = try #require(form.policy)
                #expect(policy == Self.expected(cellular: cellular, wifi: wifi, match: match, names: names))
                #expect(form.isEnabled == (cellular || wifi))
                #expect(form.savesAsAnySSID == (wifi && match != .any && names.isEmpty))
                // What the form writes reads back as the same choice (an empty list reads back as any SSID).
                let read = IOSOnDemandForm(policy: policy)
                #expect(read.policy == policy)
                #expect(read.cellular == cellular)
                #expect(read.wifi == wifi)
            }
        }
    }

    @Test
    func `an on-demand edit leaves the keys unchanged and a new key does not`() throws {
        let model = try editor(policy: .always(exceptSSIDs: []))
        #expect(model.keysUnchanged)
        model.iosOnDemand = IOSOnDemandForm(cellular: false, wifi: true)
        #expect(model.isDirty)
        #expect(model.keysUnchanged)
        model.generateKeypair()
        #expect(!model.keysUnchanged)
        // A model that opened without keys has none to keep.
        #expect(!ProfileEditorModel(profile: TunnelProfile(name: "New")).keysUnchanged)
    }

    @Test
    func `every combination saves through the editor model and survives a reopen`() throws {
        for cellular in [false, true] {
            for wifi in [false, true] {
                for match in Match.allCases {
                    for names in Self.lists {
                        let model = try editor(policy: .off)
                        model.iosOnDemand = IOSOnDemandForm(
                            cellular: cellular,
                            wifi: wifi,
                            match: match,
                            networks: names.map { .init(name: $0) },
                        )
                        let want = Self.expected(cellular: cellular, wifi: wifi, match: match, names: names)
                        #expect(model.canSave)
                        let saved = try model.validatedProfile()
                        #expect(saved.onDemand == want)
                        let reopened = try editor(policy: saved.onDemand)
                        #expect(reopened.iosOnDemand.policy == want)
                        #expect(!reopened.isDirty)
                    }
                }
            }
        }
    }

    @Test(arguments: [
        (OnDemandPolicy.off, false, false, Match.any, [String]()),
        (.always(exceptSSIDs: []), true, true, .any, []),
        (.always(exceptSSIDs: ["Home"]), true, true, .except, ["Home"]),
        (.wifiOnly(exceptSSIDs: []), false, true, .any, []),
        (.wifiOnly(exceptSSIDs: ["Home"]), false, true, .except, ["Home"]),
        (.cellularOnly, true, false, .any, []),
        (.interfaces(.wifiOrEthernet(.onlySSIDs(["Home"]))), false, false, .any, []),
        (.iosInterfaces(.wifiOnly(.onlySSIDs(["Home"]))), false, true, .only, ["Home"]),
    ])
    func `stored and legacy policies read as iOS evaluates them`(
        _ policy: OnDemandPolicy, _ cellular: Bool, _ wifi: Bool, _ match: IOSOnDemandForm.NetworkMatch, _ names: [String],
    ) {
        let form = IOSOnDemandForm(policy: policy)
        #expect(form.cellular == cellular)
        #expect(form.wifi == wifi)
        #expect(form.match == match)
        #expect(form.networks.map(\.name) == names)
    }

    @Test
    func `opening and closing the editor keeps a legacy policy as stored`() throws {
        let legacy = OnDemandPolicy.always(exceptSSIDs: ["Home"])
        let model = try editor(policy: legacy)
        #expect(!model.isDirty)
        #expect(try model.validatedProfile().onDemand == legacy)
        model.iosOnDemand.cellular = false
        #expect(try model.validatedProfile().onDemand == .iosInterfaces(.wifiOnly(.exceptSSIDs(["Home"]))))
        model.iosOnDemand.cellular = true
        #expect(try model.validatedProfile().onDemand == legacy)
        #expect(!model.isDirty)
    }

    @Test
    func `turning both toggles off saves off and is a change to discard`() throws {
        let model = try editor(policy: .iosInterfaces(.wifiOrCellular(.anySSID)))
        model.iosOnDemand.cellular = false
        model.iosOnDemand.wifi = false
        #expect(model.isDirty)
        #expect(try model.validatedProfile().onDemand == .off)
        #expect(!model.requestDiscard())
        #expect(model.showsDiscardConfirmation)
    }

    @Test
    func `a list problem blocks the save and keeps the stored policy`() throws {
        let stored = OnDemandPolicy.iosInterfaces(.wifiOnly(.anySSID))
        let model = try editor(policy: stored)
        model.iosOnDemand.match = .only
        model.iosOnDemand.addBlankRow()
        #expect(model.iosOnDemand.issues == [.nameLength])
        #expect(!model.canSave)
        #expect(model.isDirty)
        #expect(model.draft.onDemand == stored)
        model.iosOnDemand.networks[0].name = "Home"
        #expect(model.canSave)
        #expect(try model.validatedProfile().onDemand == .iosInterfaces(.wifiOnly(.onlySSIDs(["Home"]))))
        #expect(model.iosOnDemand.add("Home") == .alreadyListed)
        model.iosOnDemand.networks.append(.init(name: "Bad\u{7}"))
        #expect(model.iosOnDemand.issues == [.nameControl])
        #expect(!model.canSave)
        model.iosOnDemand.networks.removeLast()
        model.iosOnDemand.networks.append(.init(name: "Home"))
        #expect(model.iosOnDemand.issues == [.duplicate])
        #expect(!model.canSave)
    }

    @Test
    func `the list holds at most the official bound`() {
        var form = IOSOnDemandForm(wifi: true, match: .except)
        for index in 0 ..< IOSOnDemandForm.maximumNetworks {
            #expect(form.add("Net \(index)") == .added)
        }
        #expect(form.add("One more") == .listFull)
        form.addBlankRow()
        #expect(form.networks.count == IOSOnDemandForm.maximumNetworks)
        form.networks.append(.init(name: "Over"))
        #expect(form.issues == [.listLimit])
        #expect(form.policy == nil)
    }

    @Test
    func `a list is ignored while Wi-Fi is off or any SSID is chosen`() {
        let names = ["", "Home", "Home"].map { IOSOnDemandForm.Network(name: $0) }
        #expect(IOSOnDemandForm(cellular: true, wifi: false, match: .only, networks: names).policy == .iosInterfaces(.cellularOnly))
        #expect(IOSOnDemandForm(cellular: false, wifi: true, match: .any, networks: names).policy ==
            .iosInterfaces(.wifiOnly(.anySSID)))
    }

    @Test
    func `the macOS form is untouched by the iOS editor on a Mac profile`() throws {
        let mac = OnDemandPolicy.interfaces(.wifiOrEthernet(.onlySSIDs(["Home"])))
        let model = try editor(policy: mac)
        #expect(!model.iosOnDemandEdited)
        model.draft.onDemandForm.ethernet = false
        #expect(try model.validatedProfile().onDemand == .interfaces(.wifiOnly(.onlySSIDs(["Home"]))))
        #expect(model.canSave)
    }

    @Test(arguments: [
        (OnDemandPolicy.off, "Off", String?.none),
        (.iosInterfaces(.cellularOnly), "Cellular only", nil),
        (.iosInterfaces(.wifiOnly(.anySSID)), "Wi-Fi only", "Any SSID"),
        (.iosInterfaces(.wifiOrCellular(.onlySSIDs(["Home", "Cafe"]))), "Wi-Fi or cellular", "Only these SSIDs: Home, Cafe"),
        (.iosInterfaces(.wifiOnly(.exceptSSIDs(["Home"]))), "Wi-Fi only", "Except these SSIDs: Home"),
        (.always(exceptSSIDs: []), "Wi-Fi or cellular", "Any SSID"),
    ])
    func `the detail summarises the policy as the official app does`(_ policy: OnDemandPolicy, _ activation: String, _ ssids: String?) {
        let form = IOSOnDemandForm(policy: policy)
        #expect(form.activationSummary == activation)
        #expect(form.ssidSummary == ssids)
    }
}
