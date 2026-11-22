// SPDX-License-Identifier: MIT
import Foundation
import Observation
import WGEXCore

public struct ImportDuplicate: Identifiable, Hashable {
    public let id: UUID
    public let sameName: Bool
    public let samePublicKey: Bool
}

/// Review owns parsed key buffers until the caller accepts or dismisses it.
/// It does not store profiles or change the backend.
@MainActor @Observable
public final class ImportReviewModel: CustomStringConvertible, CustomReflectable {
    public var name: String
    public var existingProfiles: [TunnelProfile]
    /// The tunnel this import replaces, if the user chose to. Its own key is not a duplicate: only keys of other tunnels count.
    public var replacingID: UUID?
    /// Policy saved by either import action; IPv4 full tunnels default to blocking IPv6 outside the tunnel.
    public var ipv6Policy: IPv6Policy
    /// Whether the source needs an explicit IPv6 policy because its interface is IPv4-only with full IPv4 routes.
    public let showsIPv6PolicyChoice: Bool
    public private(set) var actionFailed = false
    public private(set) var isConfirming = false
    @ObservationIgnored private let parsed: ReviewedConfiguration?
    @ObservationIgnored private let sourceDiagnostics: [ConfigDiagnostic]

    public init(parsed: consuming ParsedConfiguration, existingProfiles: [TunnelProfile] = []) {
        name = parsed.profile.name; self.existingProfiles = existingProfiles
        showsIPv6PolicyChoice = parsed.profile.validate().contains { $0.code == .ipv6PolicyRequired }
        ipv6Policy = showsIPv6PolicyChoice ? .blockOutside : parsed.profile.protection.ipv6Policy
        sourceDiagnostics = parsed.diagnostics; self.parsed = ReviewedConfiguration(consume parsed)
    }

    /// Parser failures have no profile or keys. They remain reviewable but cannot be confirmed.
    public init(parseError: ConfigParseError, name: String = "", existingProfiles: [TunnelProfile] = []) {
        self.name = name; self.existingProfiles = existingProfiles; parsed = nil
        ipv6Policy = .tunnel; showsIPv6PolicyChoice = false
        switch parseError {
        case let .diagnostics(issues): sourceDiagnostics = issues
        case .invalidUTF8:
            sourceDiagnostics = [ConfigDiagnostic(severity: .error, code: .unknownKey, message: EditorStrings.invalidUTF8)]
        }
    }

    /// Source adapters may erase the parser's typed error. Unknown errors are never displayed verbatim.
    public convenience init(parseError: any Error, name: String = "", existingProfiles: [TunnelProfile] = []) {
        let error = (parseError as? ConfigParseError) ?? .diagnostics([
            ConfigDiagnostic(severity: .error, code: .unknownKey, message: EditorStrings.importFailed),
        ])
        self.init(parseError: error, name: name, existingProfiles: existingProfiles)
    }

    public var description: String {
        "ImportReviewModel(<redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    public var profile: TunnelProfile {
        var profile = parsed?.value.profile ?? TunnelProfile(name: name)
        profile.name = name; profile.protection.ipv6Policy = ipv6Policy
        return profile
    }

    public var duplicates: [ImportDuplicate] {
        guard parsed != nil else { return [] }
        return existingProfiles.compactMap { existing in
            let sameName = existing.name.trimmingCharacters(in: .whitespacesAndNewlines)
                .caseInsensitiveCompare(name.trimmingCharacters(in: .whitespacesAndNewlines)) == .orderedSame
            let sameKey = existing.id != replacingID && existing.interface.publicKey == profile.interface.publicKey
            return sameName || sameKey ? ImportDuplicate(id: existing.id, sameName: sameName, samePublicKey: sameKey) : nil
        }
    }

    /// The tunnel Replace would overwrite: the first existing tunnel with the same name or key, whether or not it is
    /// already marked as replaced, so the choice stays on screen after it clears the key refusal.
    public var replacementCandidate: UUID? {
        guard parsed != nil else { return nil }
        let wanted = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = profile.interface.publicKey
        return existingProfiles.first {
            $0.name.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare(wanted) == .orderedSame
                || $0.interface.publicKey == key
        }?.id
    }

    /// Marks the candidate as the tunnel being replaced (or clears it), so its own key is not a duplicate.
    public func setReplacing(_ replacing: Bool) {
        replacingID = replacing ? replacementCandidate : nil
    }

    public var keyInUseElsewhere: Bool {
        duplicates.contains(where: \.samePublicKey)
    }

    public var diagnostics: [ConfigDiagnostic] {
        // Revalidate edited fields. Only the original IPv6-policy diagnostic is replaced by current validation.
        guard parsed != nil else { return sourceDiagnostics }
        let validation = profile.validate(publicKeysInUse: Set(existingProfiles.filter { $0.id != replacingID }.map(\.interface.publicKey)))
        var seen = Set<ConfigDiagnostic>()
        return (sourceDiagnostics.filter { $0.code != .ipv6PolicyRequired } + validation).filter { seen.insert($0).inserted }
    }

    public var errors: [ConfigDiagnostic] {
        diagnostics.filter { $0.severity == .error }
    }

    public var warnings: [ConfigDiagnostic] {
        diagnostics.filter { $0.severity == .warning }
    }

    public var canImport: Bool {
        parsed != nil && errors.isEmpty && !isConfirming
    }

    /// Borrowed bytes are valid only during this callback. Owners must explicitly copy into their transaction.
    @discardableResult
    public func confirm(using action: (TunnelProfile, borrowing ParsedSecrets) throws -> Void) -> Bool {
        guard canImport, let parsed else { return false }
        isConfirming = true
        defer { isConfirming = false }
        do { try action(profile, parsed.value.secrets); actionFailed = false; return true }
        catch { actionFailed = true; return false }
    }
}

/// A reference wrapper permits an optional uniquely owned parse result without copying its keys.
private final class ReviewedConfiguration {
    let value: ParsedConfiguration
    init(_ value: consuming ParsedConfiguration) {
        self.value = value
    }
}
