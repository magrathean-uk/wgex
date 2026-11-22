// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    /// M08-T03 (DEC-087): the Exclusions row and warning line on the tunnel page, the Edit sheet's Exclusions section and the
    /// `# WGEX-Exclude =` line through Edit as Text.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacExclusionsTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)

        // MARK: Tunnel page

        private func home(exclusions: [String] = []) throws -> TunnelProfile {
            var profile = TunnelProfile(name: "Home")
            profile.interface.addresses = try [IPAddressRange("10.8.0.2/24")]
            profile.interface.dns = try [DNSServer("10.8.0.1")]
            profile.peers = try [.init(
                publicKey: profile.interface.publicKey, allowedIPs: [.allIPv4], endpoint: Endpoint("vpn.example.net:51820"),
            )]
            profile.exclusions = try TunnelExclusions(entries: exclusions)
            return profile
        }

        private func shell(
            _ profile: TunnelProfile, active: Bool, protection: ProtectionState = .protected, unresolved: [String] = [],
        ) -> MacShellModel {
            let phase: TunnelPhase = if !active {
                .idle
            } else if protection == .blocked {
                .failed(.backendUnavailable, blockedByPolicy: true, needsSecrets: false)
            } else {
                .active(Generation(rawValue: 1))
            }
            var status = TunnelStatus(
                phase: phase, protection: active ? protection : .unprotected, transport: nil, health: .idle, recentEvents: [],
            )
            status.activeProfileID = active ? profile.id : nil
            status.measuredAt = date
            status.unresolvedExclusions = unresolved
            return MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [profile], status: status, now: date,
            )
        }

        private func protection(_ model: MacShellModel) throws -> MacTunnelPagePresentation.Group {
            try #require(MacTunnelPagePresentation(model: model, profile: model.profiles[0]).groups.first { $0.id == "protection" })
        }

        @Test func `the exclusions row reads None without entries and is not a link`() throws {
            let group = try protection(shell(home(), active: false))
            let row = try #require(group.rows.first { $0.id == "exclusions" })
            #expect(row.label == "Exclusions")
            #expect(row.value == "None")
            #expect(row.link == nil)
            #expect(group.rows.map(\.id) == ["killSwitch", "localNetwork", "exclusions", "onDemand", "startup"])
        }

        @Test func `the exclusions row counts entries, copies them and leads to the list`() throws {
            let model = try shell(home(exclusions: ["192.0.2.0/24", "Example.COM", "2001:db8::/32"]), active: false)
            let page = MacTunnelPagePresentation(model: model, profile: model.profiles[0])
            let row = try #require(page.groups.flatMap(\.rows).first { $0.id == "exclusions" })
            #expect(row.value == "3 exclusions")
            #expect(row.link == .exclusions)
            #expect(row.copyValue == "192.0.2.0/24, 2001:db8::/32, example.com")
            #expect(page.exclusions == ["192.0.2.0/24", "2001:db8::/32", "example.com"])
            let one = try protection(shell(home(exclusions: ["198.51.100.7"]), active: false))
            #expect(one.rows.first { $0.id == "exclusions" }?.value == "1 exclusion")
        }

        @Test func `unresolved host names show as a warning line only while this tunnel is up`() throws {
            let profile = try home(exclusions: ["example.com", "example.net"])
            let up = try protection(shell(profile, active: true, unresolved: ["example.com"]))
            #expect(up.note == "Could not look up example.com. Traffic to it stays in the tunnel.")
            let two = try protection(shell(profile, active: true, unresolved: ["example.com", "example.net"]))
            #expect(two.note == UserStrings.exclusionUnresolved(["example.com", "example.net"]))
            #expect(try protection(shell(profile, active: true)).note == nil)
            #expect(try protection(shell(profile, active: false, unresolved: ["example.com"])).note == nil)
            #expect(try protection(shell(profile, active: true, protection: .blocked, unresolved: ["example.com"])).note == nil)
        }

        // MARK: Editor

        private func editor(exclusions: [String] = []) throws -> ProfileEditorModel {
            let parsed = try EditorFixtures.parsed("single-peer-full-tunnel")
            var profile = parsed.profile
            profile.protection.ipv6Policy = .allowOutside
            profile.exclusions = try TunnelExclusions(entries: exclusions)
            return try ProfileEditorModel(profile: profile, secrets: parsed.secrets, allowsIncomplete: true)
        }

        @Test func `the editor lists saved exclusions one per line in the core's spelling`() throws {
            let model = try editor(exclusions: ["198.51.100.7/32", "Example.COM.", "2001:db8::1/32"])
            #expect(model.draft.exclusions == ["198.51.100.7", "2001:db8::/32", "example.com"])
            #expect(!model.isDirty)
            #expect(try model.validatedProfile().exclusions == model.sourceProfile.exclusions)
        }

        @Test func `Add takes valid entries in canonical form and Remove drops them`() throws {
            let model = try editor()
            #expect(model.exclusionValidation("") == .empty)
            #expect(model.exclusionValidation("203.0.113.9/24") == .valid)
            #expect(model.addExclusion(" 203.0.113.9/24 "))
            #expect(model.addExclusion("Example.COM."))
            #expect(model.addExclusion("2001:db8::"))
            #expect(model.draft.exclusions == ["203.0.113.0/24", "example.com", "2001:db8::"])
            #expect(model.isDirty)
            let saved = try model.validatedProfile()
            #expect(saved.exclusions.ranges.map(\.stringRepresentation) == ["203.0.113.0/24", "2001:db8::/128"])
            #expect(saved.exclusions.hostNames == ["example.com"])
            model.removeExclusion("example.com")
            #expect(model.draft.exclusions == ["203.0.113.0/24", "2001:db8::"])
            #expect(try model.validatedProfile().exclusions.hostNames.isEmpty)
        }

        @Test func `Add refuses what the core refuses, with the core's words`() throws {
            let model = try editor(exclusions: ["198.51.100.0/24"])
            let cases: [(String, String)] = [
                ("not a host!", UserStrings.exclusionHostName),
                ("192.0.2.0/33", UserStrings.exclusionHostName),
                ("0.0.0.0/0", UserStrings.exclusionDefaultRoute),
                ("10.77.0.0/24", UserStrings.exclusionOverlapsTunnel),
                ("10.77.0.1", UserStrings.exclusionOverlapsTunnel),
                ("192.0.2.1", UserStrings.exclusionOverlapsTunnel),
                ("198.51.100.7/24", MacStrings.exclusionAlreadyListed),
            ]
            for (text, message) in cases {
                #expect(model.exclusionValidation(text) == .invalid(message), "\(text)")
                #expect(!model.addExclusion(text), "\(text)")
            }
            #expect(model.draft.exclusions == ["198.51.100.0/24"])
            #expect(model.canSave)
        }

        @Test func `the 65th entry is refused with the core's limit message`() throws {
            let model = try editor(exclusions: (1 ... 64).map { "host\($0).example.com" })
            #expect(model.exclusionValidation("one-more.example.com") == .invalid(UserStrings.exclusionLimit))
            #expect(!model.addExclusion("one-more.example.com"))
            #expect(model.draft.exclusions.count == 64)
        }

        @Test func `a later change that makes an exclusion invalid blocks Save under Exclusions`() throws {
            let model = try editor(exclusions: ["198.51.100.0/24"])
            #expect(model.canSave)
            model.draft.addresses = "198.51.100.5/32"
            #expect(!model.canSave)
            #expect(model.diagnostics(for: .exclusions).map(\.message) == [UserStrings.exclusionOverlapsTunnel])
            model.removeExclusion("198.51.100.0/24")
            #expect(model.canSave)
            model.draft.exclusions.append("bad entry!")
            #expect(model.diagnostics(for: .exclusions).map(\.message) == [UserStrings.exclusionHostName])
            #expect(!model.canSave)
            #expect(!model.canEditAsText)
            #expect(EditorField.exclusions.automationKey == "exclusions")
        }

        // MARK: Edit as Text

        @Test func `the exclude line round-trips through Edit as Text`() throws {
            let model = try editor(exclusions: ["198.51.100.0/24", "example.com"])
            let draft = model.draft
            let text = try model.configurationTextForEditing()
            #expect(text.contains("# WGEX-Exclude = 198.51.100.0/24, example.com\n"))
            var bytes = Array(text.utf8)
            #expect(try model.applyConfigurationText(&bytes).isEmpty)
            #expect(model.draft == draft)
            #expect(try model.validatedProfile().exclusions == model.sourceProfile.exclusions)
        }

        @Test func `editing the exclude line in text changes the list and removing it clears it`() throws {
            let model = try editor(exclusions: ["198.51.100.0/24"])
            let text = try model.configurationTextForEditing()
            var edited = Array(text.replacingOccurrences(
                of: "# WGEX-Exclude = 198.51.100.0/24", with: "# wgex-exclude = 203.0.113.9, Example.NET",
            ).utf8)
            try model.applyConfigurationText(&edited)
            #expect(model.draft.exclusions == ["203.0.113.9", "example.net"])
            #expect(try model.configurationTextForEditing().contains("# WGEX-Exclude = 203.0.113.9, example.net\n"))
            var removed = try Array(model.configurationTextForEditing().split(separator: "\n", omittingEmptySubsequences: false)
                .filter { !$0.hasPrefix("# WGEX-Exclude") }.joined(separator: "\n").utf8)
            try model.applyConfigurationText(&removed)
            #expect(model.draft.exclusions.isEmpty)
            #expect(try model.validatedProfile().exclusions.isEmpty)
        }

        @Test func `a bad exclude line in text is refused and changes nothing`() throws {
            let model = try editor(exclusions: ["198.51.100.0/24"])
            let draft = model.draft
            var bytes = try Array(model.configurationTextForEditing().replacingOccurrences(
                of: "# WGEX-Exclude = 198.51.100.0/24", with: "# WGEX-Exclude = 198.51.100.0/40",
            ).utf8)
            #expect(throws: ConfigParseError.self) { try model.applyConfigurationText(&bytes) }
            #expect(model.draft == draft)
        }

        // MARK: Identifiers and words

        @Test func `new controls are catalogued and the words follow SPEC 3`() {
            let ids = Set(WGEXAccessibility.catalogue.map(\.id))
            for id in [
                "wgex.main.exclusionWarning", "wgex.main.exclusion", "wgex.editor.exclusion", "wgex.editor.exclusionInput",
                "wgex.editor.exclusionProblem", "wgex.editor.addExclusion", "wgex.editor.removeExclusion",
                "wgex.editor.exclusionsNote",
            ] {
                #expect(ids.contains(id), "\(id)")
            }
            #expect(MacStrings.exclusionsNote == "Traffic to these addresses and names skips the tunnel and the kill switch.")
            #expect(MacStrings.addExclusion == "Add")
            #expect(MacStrings.removeExclusion == "Remove")
            #expect(MacStrings.exclusionsCatalogue.allSatisfy { !$0.localizedCaseInsensitiveContains("profile") })
        }
    }
#endif
