// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct ImportReviewTests {
    @Test(arguments: [["0.0.0.0/0"], ["0.0.0.0/1", "128.0.0.0/1"], ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]])
    func `full IPv4 import defaults to blocking IPv6 and confirms the selected policy`(_ routes: [String]) throws {
        var bytes = try EditorFixtures.bytes("single-peer-full-tunnel")
        let original = Array("AllowedIPs = 0.0.0.0/0".utf8)
        let start = try #require(bytes.indices.first { bytes[$0...].starts(with: original) })
        bytes.replaceSubrange(start ..< start + original.count, with: "AllowedIPs = \(routes.joined(separator: ", "))".utf8)
        let parsed = try parseWgQuick(&bytes, name: "Home")
        #expect(parsed.diagnostics.contains { $0.code == .ipv6PolicyRequired })
        let model = ImportReviewModel(parsed: consume parsed)
        #expect(model.showsIPv6PolicyChoice)
        #expect(model.ipv6Policy == .blockOutside)
        #expect(model.errors.isEmpty)
        #expect(model.canImport)
        var confirmedPolicy: IPv6Policy?
        #expect(model.confirm { profile, _ in confirmedPolicy = profile.protection.ipv6Policy })
        #expect(confirmedPolicy == .blockOutside)
        model.ipv6Policy = .allowOutside
        #expect(model.canImport)
        #expect(model.confirm { profile, _ in confirmedPolicy = profile.protection.ipv6Policy })
        #expect(confirmedPolicy == .allowOutside)
    }

    @Test
    func `dual stack import keeps tunnel IPv6 without a policy choice`() throws {
        let model = try ImportReviewModel(parsed: EditorFixtures.parsed())
        #expect(!model.showsIPv6PolicyChoice)
        #expect(model.ipv6Policy == .tunnel)
        #expect(model.canImport)
    }

    @Test
    func `IPv6 default does not clear unrelated diagnostics`() throws {
        var parsed = try EditorFixtures.parsed("single-peer-full-tunnel")
        parsed.profile.interface.addresses = []
        let model = ImportReviewModel(parsed: consume parsed)
        #expect(model.showsIPv6PolicyChoice)
        #expect(model.errors.contains { $0.code == .noAddresses })
        #expect(!model.canImport)
    }

    @Test
    func `clean import invokes only the selected injected action`() throws {
        let model = try ImportReviewModel(parsed: EditorFixtures.parsed())
        #expect(model.canImport)
        var imported = false
        let success = model.confirm { profile, secrets in
            imported = true
            #expect(profile.name == "Home")
            #expect(secrets.references.count > 0)
        }
        #expect(success && imported)
        #expect(!model.isConfirming)
    }

    @Test
    func `errors block confirmation warnings remain grouped and actionable`() throws {
        var parsed = try EditorFixtures.parsed()
        parsed.profile.interface.addresses = []
        parsed.profile.protection.dnsPolicy = .systemDefault
        let model = ImportReviewModel(parsed: consume parsed)
        #expect(!model.errors.isEmpty)
        #expect(!model.warnings.isEmpty)
        #expect(!model.canImport)
        var invoked = false
        let confirmed = model.confirm { _, _ in invoked = true }
        #expect(!confirmed && !invoked)
    }

    @Test
    func `duplicates distinguish interface public key and case insensitive name`() throws {
        let parsed = try EditorFixtures.parsed()
        var sameName = TunnelProfile(name: "home")
        sameName.interface.publicKey = try PublicKey(rawValue: Data(repeating: 99, count: 32))
        var sameKey = parsed.profile
        sameKey.name = "Another name"
        let model = ImportReviewModel(parsed: consume parsed, existingProfiles: [sameName, sameKey])
        #expect(model.duplicates.count == 2)
        #expect(model.duplicates.contains { $0.sameName && !$0.samePublicKey })
        #expect(model.duplicates.contains { !$0.sameName && $0.samePublicKey })
        #expect(model.keyInUseElsewhere)
        #expect(model.warnings.contains { $0.code == .keyInUseElsewhere })
        model.name = "New name"
        #expect(model.duplicates.count == 1)
        #expect(model.canImport)
        model.name = ""
        #expect(!model.canImport)
    }

    @Test
    func `replacing a tunnel leaves its own key out of the duplicate check but not another tunnel's`() throws {
        let parsed = try EditorFixtures.parsed()
        var target = parsed.profile
        target.name = "Target"
        let other = TunnelProfile(
            id: UUID(), name: "Other", interface: parsed.profile.interface, peers: parsed.profile.peers,
            secrets: parsed.profile.secrets, protection: parsed.profile.protection,
        )
        let model = ImportReviewModel(parsed: consume parsed, existingProfiles: [target, other])
        model.name = "New name"
        #expect(model.keyInUseElsewhere)
        model.replacingID = target.id
        #expect(model.keyInUseElsewhere)
        #expect(model.duplicates.map(\.id) == [other.id])
        model.replacingID = nil
        model.existingProfiles = [target]
        #expect(model.keyInUseElsewhere)
        model.replacingID = target.id
        #expect(!model.keyInUseElsewhere)
        #expect(model.duplicates.isEmpty)
        #expect(!model.warnings.contains { $0.code == .keyInUseElsewhere })
        #expect(model.canImport)
    }

    @Test
    func `choosing Replace accepts the same key and the choice stays offered`() throws {
        let parsed = try EditorFixtures.parsed()
        var target = parsed.profile
        target.name = "Target"
        let model = ImportReviewModel(parsed: consume parsed, existingProfiles: [target])
        model.name = "Renamed"
        #expect(model.replacementCandidate == target.id)
        #expect(model.keyInUseElsewhere)
        model.setReplacing(true)
        #expect(model.replacingID == target.id)
        #expect(model.replacementCandidate == target.id)
        #expect(!model.keyInUseElsewhere)
        #expect(model.canImport)
        model.setReplacing(false)
        #expect(model.replacingID == nil)
        #expect(model.keyInUseElsewhere)
    }

    @Test
    func `parser errors can be reviewed without inventing a valid profile`() {
        let error = ConfigParseError.diagnostics([ConfigDiagnostic(severity: .error, code: .limitExceeded)])
        let model = ImportReviewModel(parseError: error, name: "Home")
        #expect(model.errors.map(\.code) == [.limitExceeded])
        #expect(model.warnings.isEmpty)
        #expect(!model.canImport)
        #expect(model.duplicates.isEmpty)
        model.name = "Changed"
        let invoked = model.confirm { _, _ in Issue.record("Rejected input cannot be imported") }
        #expect(!invoked)
    }

    @Test
    func `ignored hooks remain warnings in import review`() throws {
        let model = try ImportReviewModel(parsed: EditorFixtures.parsed("with-hooks-rejected"))
        #expect(model.errors.isEmpty)
        #expect(model.warnings.contains { $0.code == .ignoredHook })
        #expect(model.canImport)
    }

    @Test
    func `erased parser errors preserve diagnostics and unknown errors stay opaque`() {
        let erased: any Error = ConfigParseError.diagnostics([ConfigDiagnostic(severity: .error, code: .invalidCIDR)])
        let parserReview = ImportReviewModel(parseError: erased)
        #expect(parserReview.errors.map(\.code) == [.invalidCIDR])
        let unknown = ImportReviewModel(parseError: CocoaError(.fileReadNoSuchFile))
        #expect(!unknown.canImport)
        #expect(unknown.errors.map(\.message) == [EditorStrings.importFailed])
    }

    @Test
    func `callback failure leaves review available and descriptions redacted`() throws {
        let model = try ImportReviewModel(parsed: EditorFixtures.parsed())
        let success = model.confirm { _, _ in throw ConfigurationError.invalidPort }
        #expect(!success && model.actionFailed && model.canImport)
        let leaked = try EditorFixtures.containsSecret(String(describing: model) + String(reflecting: model))
        #expect(!leaked)
        #expect(Mirror(reflecting: model).children.isEmpty)
    }
}
