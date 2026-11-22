// SPDX-License-Identifier: MIT
import Foundation
import Observation
import WGEXCore

/// Explicit confirmation is required for each file or QR containing keys.
@MainActor @Observable
public final class ExportModel: CustomStringConvertible, CustomReflectable {
    public enum Purpose: Sendable { case file, qr }
    public let profile: TunnelProfile
    public private(set) var pendingPurpose: Purpose?
    @ObservationIgnored private var confirmedPurpose: Purpose?
    @ObservationIgnored private let backing: ParsedConfiguration

    /// Only supply `original` metadata while the profile remains unedited.
    public init(profile: TunnelProfile, secrets: consuming ParsedSecrets) {
        self.profile = profile
        backing = ParsedConfiguration(
            profile: profile,
            diagnostics: [],
            secrets: consume secrets,
            original: profile.original ?? OriginalText(text: "", sha256OfOriginal: Data()),
        )
    }

    public init(parsed: consuming ParsedConfiguration) {
        profile = parsed.profile; backing = parsed
    }

    public var description: String {
        "ExportModel(<redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    public var shareableText: String {
        serialiseWgQuick(profile)
    }

    public var suggestedFilename: String {
        "WireGuard.conf"
    }

    public func request(_ purpose: Purpose) {
        confirmedPurpose = nil; pendingPurpose = purpose
    }

    public func cancel() {
        pendingPurpose = nil; confirmedPurpose = nil
    }

    public func confirm() {
        confirmedPurpose = pendingPurpose; pendingPurpose = nil
    }

    /// A one-use grant; no secret String or system-share representation is available.
    public func confirmedFileText() throws -> SecretText {
        guard confirmedPurpose == .file else { throw ExportError.confirmationRequired }
        confirmedPurpose = nil
        if let original = profile.original {
            return try exportOriginalWgQuick(original, secrets: backing.secrets)
        }
        return try serialiseWgQuick(profile, secrets: backing.secrets)
    }

    /// Normalised wg-quick bytes for the QR renderer, including the keys.
    public func confirmedQRPayload() throws -> SecretText {
        guard confirmedPurpose == .qr else { throw ExportError.confirmationRequired }
        confirmedPurpose = nil
        return try serialiseWgQuick(profile, secrets: backing.secrets)
    }
}

public nonisolated enum ExportError: Error, Sendable {
    case confirmationRequired, fileWriteFailed, unsupportedPlatform
}
