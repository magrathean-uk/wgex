// SPDX-License-Identifier: MIT

// Lab signatures are ad hoc: they have no certificate chain or team, so neither
// anchor apple generic nor certificate clauses can match. Lab peers are pinned
// by identifier and cdhash instead. WGEX_LAB_BUILD is only set by just lab build;
// this variant must never ship in Debug/Release distribution builds.
import Foundation
import WGEXCore

#if WGEX_LAB_BUILD && WGEX_OWN_MAC_BUILD
    #error("WGEX_LAB_BUILD and WGEX_OWN_MAC_BUILD cannot be combined")
#endif

/// Code-signing requirement strings for the XPC connection (02 §5, ADR-012),
/// derived from ``BuildIdentifiers``. Debug and Release differ in base
/// (`.dev`) and therefore in Mach service, so they can never talk to each other.
public struct RequirementStrings: Sendable, Hashable {
    /// Signing flavour.
    public enum Variant: Sendable, Hashable {
        /// Development signing; any certificate of the team.
        case debug
        /// Developer ID signing without `get-task-allow`.
        case release
        #if WGEX_OWN_MAC_BUILD
            /// The specific own-Mac Apple Development identity, without `get-task-allow`.
            case ownMac
        #endif
        #if WGEX_LAB_BUILD
            /// Ad hoc lab signing; exact sibling binary hashes only. Never ships.
            case lab
        #endif
    }

    /// Developer ID intermediate certificate marker.
    private static let developerIDIntermediate = "certificate 1[field.1.2.840.113635.100.6.2.6]"
    /// Developer ID Application leaf certificate marker.
    private static let developerIDLeaf = "certificate leaf[field.1.2.840.113635.100.6.1.13]"
    #if WGEX_OWN_MAC_BUILD
        // The pinned team and leaf come from the generated, git-ignored
        // Generated/OwnMacIdentity.generated.swift, which build-own-mac.sh writes from Config/Local.xcconfig.
        private static let ownMacTeam = OwnMacIdentity.team
        private static let ownMacLeaf = OwnMacIdentity.leaf
    #endif

    /// Strings for the running build.
    public static var current: RequirementStrings {
        current(for: .current)
    }

    /// Strings selected for explicit build identifiers.
    package static func current(for identifiers: BuildIdentifiers) -> RequirementStrings {
        #if WGEX_LAB_BUILD
            RequirementStrings(identifiers: identifiers, variant: .lab)
        #elseif WGEX_OWN_MAC_BUILD
            RequirementStrings(identifiers: identifiers, variant: identifiers.isDevelopment ? .debug : .ownMac)
        #else
            RequirementStrings(identifiers: identifiers)
        #endif
    }

    /// Debug strings (development base).
    public static var debug: RequirementStrings {
        RequirementStrings(identifiers: BuildIdentifiers.current.developmentVariant)
    }

    /// Release strings (release base).
    public static var release: RequirementStrings {
        RequirementStrings(identifiers: BuildIdentifiers.current.releaseVariant)
    }

    /// Identifiers the strings are built from.
    public let identifiers: BuildIdentifiers

    /// Builds strings for `identifiers`; the variant follows the base unless supplied.
    public init(identifiers: BuildIdentifiers, variant: Variant? = nil) {
        self.identifiers = identifiers
        selectedVariant = variant ?? (identifiers.isDevelopment ? .debug : .release)
    }

    private let selectedVariant: Variant

    /// Selected signing policy; current lab builds use the lab variant.
    public var variant: Variant {
        selectedVariant
    }

    /// Requirement for the enclosing app, using the same certificate policy as XPC.
    public var appRequirement: String {
        requirement(identifierClause: "identifier \"\(identifiers.app)\"")
    }

    /// Requirement the app and CLI place on the daemon.
    public var daemonRequirement: String {
        requirement(identifierClause: "identifier \"\(identifiers.daemon)\"")
    }

    /// Requirement the daemon places on its clients (the app or the CLI).
    public var clientRequirement: String {
        requirement(identifierClause: "identifier \"\(identifiers.app)\" or identifier \"\(identifiers.cli)\"")
    }

    #if WGEX_LAB_BUILD
        /// No valid signed peer has this cdhash. Used when every peer is refused.
        public static let labDenyAll = "cdhash H\"0000000000000000000000000000000000000000\""

        /// One clause per peer and slice. Empty peers deny all; missing hashes throw.
        public static func lab(identifierHashes: [(identifier: String, cdhashes: [Data])]) throws -> String {
            var clauses: [String] = []
            for (identifier, hashes) in identifierHashes {
                guard !identifier.isEmpty, identifier.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || ".-".contains($0)) }) else {
                    throw DaemonFailure(code: .securityLabInvalidIdentifier)
                }
                guard !hashes.isEmpty else { throw DaemonFailure(code: .securityLabMissingHash) }
                for hash in hashes {
                    guard hash.count == 20 else { throw DaemonFailure(code: .securityLabInvalidHash) }
                    let hex = hash.map { String(format: "%02x", $0) }.joined()
                    clauses.append("(identifier \"\(identifier)\" and cdhash H\"\(hex)\")")
                }
            }
            return clauses.isEmpty ? labDenyAll : clauses.joined(separator: " or ")
        }
    #endif

    private func requirement(identifierClause: String) -> String {
        let team = "certificate leaf[subject.OU] = \"\(identifiers.team)\""
        switch variant {
        case .debug:
            return "anchor apple generic and \(team) and (\(identifierClause))"
        #if WGEX_OWN_MAC_BUILD
            case .ownMac:
                // The WWDR intermediate marker is deliberately omitted: it is unverified against a real certificate.
                return "anchor apple generic and certificate leaf[subject.OU] = \"\(Self.ownMacTeam)\" "
                    + "and certificate leaf[subject.CN] = \"\(Self.ownMacLeaf)\" and (\(identifierClause)) "
                    + "and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        #endif
        #if WGEX_LAB_BUILD
            case .lab:
                // Callers must supply sibling hashes via lab(identifierHashes:).
                return Self.labDenyAll
        #endif
        case .release:
            return "anchor apple generic and \(Self.developerIDIntermediate) and \(Self.developerIDLeaf) and \(team) "
                + "and (\(identifierClause)) and !(entitlement[\"com.apple.security.get-task-allow\"] exists)"
        }
    }
}
