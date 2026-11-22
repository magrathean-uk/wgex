// SPDX-License-Identifier: MIT

import Foundation
import Observation
import WGEXCore

/// tvOS policy preferences; routing enforcement remains a provider responsibility.
public nonisolated struct TVSettings: Codable, Sendable, Equatable {
    public var alwaysOn = true
    public var allowLAN = true
    public var dnsPolicy: DNSPolicy = .tunnelAll
    public var eventsOnScreen = false
    public var privacyAccepted = false
    public init() {}

    public func applying(to source: TunnelProfile) -> TunnelProfile {
        var profile = source
        profile.onDemand = alwaysOn ? .always(exceptSSIDs: []) : .off
        profile.protection.tv = TVProtection(enforceRoutes: true, allowLAN: allowLAN)
        profile.protection.dnsPolicy = dnsPolicy
        return profile
    }
}

/// Strict TV mapping, including impossible reports during transitional phases.
public nonisolated enum TVConnectionState {
    public static func presentation(_ status: TunnelStatus, now: Date = Date(), staleness: Staleness = .fresh) -> ProtectionPresentation {
        var safe = status
        let inconsistent = switch (status.protection, status.phase) {
        case (.blocked, _), (.captiveWindow, _), (_, .captiveWindow): true
        default: false
        }
        if inconsistent {
            safe.protection = .unknown
        }
        return ProtectionPresentation(status: safe, context: ProtectionContext(
            platform: .tvOS, now: now, staleness: staleness,
            unknownReason: inconsistent ? .inconsistentState : .extensionUnavailable,
        ))
    }

    public static func isRunning(_ phase: TunnelPhase) -> Bool {
        switch phase {
        case .active, .preparing, .configuring, .reasserting, .stopping: true
        default: false
        }
    }

    /// Impossible protection events must not reintroduce a blocking claim in the timeline.
    public static func events(_ events: [TunnelEvent]) -> [TunnelEvent] {
        events.map { event in
            var safe = event
            switch event.kind {
            case .protectionChanged(.blocked), .protectionChanged(.captiveWindow): safe.kind = .protectionChanged(.unknown)
            default: break
            }
            return safe
        }
    }
}

/// The native field necessarily holds text transiently; it is cleared before review and on dismissal.
@MainActor @Observable
public final class TVPasteImportModel: CustomStringConvertible, CustomReflectable {
    public var text = ""
    public private(set) var review: ImportReviewModel?
    public init() {}
    public var description: String {
        "TVPasteImportModel(<redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    public func prepare(existing: [TunnelProfile] = []) {
        prepare(bytes: Array(text.utf8), existing: existing)
    }

    /// Imports owned bytes and wipes them before returning, without a secret-bearing String.
    public func prepare(bytes input: consuming [UInt8], existing: [TunnelProfile] = []) {
        var bytes = input
        text = ""; review = nil
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        do {
            var parsed = try parseWgQuick(&bytes)
            parsed.profile.name = "Apple TV"
            parsed.profile.onDemand = .always(exceptSSIDs: [])
            if !parsed.profile.interface.addresses.contains(where: \.isIPv6) {
                parsed.profile.protection.ipv6Policy = .blockOutside
            }
            let reviewed = try ParsedConfiguration(
                profile: parsed.profile,
                diagnostics: parsed.diagnostics.filter { $0.code != .ipv6PolicyRequired },
                secrets: Self.copySecrets(parsed.secrets),
                original: parsed.original,
            )
            review = ImportReviewModel(parsed: reviewed, existingProfiles: existing)
        } catch let error as ConfigParseError {
            review = ImportReviewModel(parseError: error, existingProfiles: existing)
        } catch {
            review = ImportReviewModel(parseError: .diagnostics([
                ConfigDiagnostic(severity: .error, code: .invalidKey),
            ]), existingProfiles: existing)
        }
    }

    private static func copySecrets(_ source: borrowing ParsedSecrets) throws -> ParsedSecrets {
        var bytes = try SecretBytes(zeroedCount: source.references.count * 32)
        var references: [SecretRef: Range<Int>] = [:]
        for (index, reference) in source.references.keys.enumerated() {
            let range = index * 32 ..< (index + 1) * 32
            try source.withKey(reference) { key in
                bytes.withUnsafeMutableBytes { destination in
                    UnsafeMutableRawBufferPointer(rebasing: destination[range]).copyMemory(from: key)
                }
            }
            references[reference] = range
        }
        return try ParsedSecrets(bytes: bytes, references: references)
    }

    public func clear() {
        text = ""; review = nil
    }
}
