// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXProfileStore

/// Shared secret/document operations. Callers serialise edits and retain their own UI and backend wiring.
public nonisolated struct ProfileComposition: Sendable {
    /// Persisted formats are deliberately distinct; neither strategy migrates existing documents.
    public enum Strategy: Sendable {
        case persistentReferences(any PersistentReferenceSecretStore)
        case identities(any SecretStore)
    }

    public enum InstallOrder: Sendable { case beforeDocument, afterDocument }

    private let strategy: Strategy

    public init(strategy: Strategy) {
        self.strategy = strategy
    }

    /// Stores keys, commits the public document and installs it in the platform's existing order. On failure,
    /// newly created items are removed and replaced identity items restored. Old items retire only after success.
    public func commit(
        _ profile: TunnelProfile, secrets: borrowing ParsedSecrets, to store: ProfileStore,
        previous: TunnelProfile? = nil, installOrder: InstallOrder = .afterDocument,
        install: (TunnelProfile) async throws -> Void = { _ in }, rollback: () async -> Void = {},
    ) async throws -> TunnelProfile {
        let transaction = SecretTransaction(strategy: strategy)
        let saved: TunnelProfile
        do { saved = try await transaction.store(profile, secrets: secrets) }
        catch {
            if installOrder == .beforeDocument {
                await rollback()
            }
            throw error
        }
        do {
            if installOrder == .beforeDocument {
                try await install(saved)
            }
            try await store.save(saved)
            if installOrder == .afterDocument {
                try await install(saved)
            }
        } catch {
            if installOrder == .afterDocument {
                if let previous {
                    try? await store.save(previous)
                } else {
                    try? await store.delete(profile.id)
                }
                await rollback()
                await transaction.rollback()
            } else {
                await transaction.rollback()
                await rollback()
            }
            throw error
        }
        if let previous {
            let bestEffort = switch strategy {
            case .persistentReferences: false
            case .identities: true
            }
            try? await deleteSecrets(of: previous, keeping: saved, bestEffort: bestEffort)
        }
        return saved
    }

    /// Always reload from the store, including after a relaunch; no editor-owned state participates.
    public func load(_ profile: TunnelProfile) async throws -> ParsedSecrets {
        let references: [SecretRef] = switch strategy {
        case .persistentReferences:
            // The iOS editor loads WireGuard keys only, as the original bridge did.
            ([profile.secrets.privateKey] + Array(profile.secrets.presharedKeys.values))
                .reduce(into: []) {
                    if !$0.contains($1) {
                        $0.append($1)
                    }
                }
        case .identities:
            Self.references(of: profile)
        }
        var bytes = try SecretBytes(zeroedCount: references.count * 32)
        var ranges: [SecretRef: Range<Int>] = [:]
        for (index, reference) in references.enumerated() {
            let key: SecretBytes
            switch strategy {
            case let .persistentReferences(store):
                guard case let .keychain(persistent) = reference else { throw ConfigurationError.invalidSecretReference }
                key = try await store.load(persistentReference: persistent)
            case let .identities(store):
                key = try await store.load(Self.identity(reference, profile: profile))
            }
            guard key.count == 32 else { throw ConfigurationError.invalidSecretReference }
            try key.copyBytes(into: &bytes, at: index * 32)
            ranges[reference] = index * 32 ..< (index + 1) * 32
        }
        return try ParsedSecrets(bytes: bytes, references: ranges)
    }

    /// A missing item is already retired. Other failures propagate so the caller can retain the document for retry.
    /// With bestEffort, attempt every retirement before reporting the first failure (the tvOS cleanup policy).
    public func deleteSecrets(of profile: TunnelProfile, keeping kept: TunnelProfile? = nil, bestEffort: Bool = false) async throws {
        let keep = Set(kept.map(Self.references(of:)) ?? [])
        var firstFailure: any Error?
        for reference in Self.references(of: profile) where !keep.contains(reference) {
            do {
                switch strategy {
                case let .persistentReferences(store):
                    guard case let .keychain(persistent) = reference else { continue }
                    try await store.delete(persistentReference: persistent)
                case let .identities(store):
                    try await store.delete(Self.identity(reference, profile: profile))
                }
            } catch SecretStoreError.notFound { /* Retirement is idempotent. */ }
            catch {
                guard bestEffort else { throw error }
                if firstFailure == nil {
                    firstFailure = error
                }
            }
        }
        if let firstFailure {
            throw firstFailure
        }
    }

    public static func copySecrets(_ source: borrowing ParsedSecrets) throws -> ParsedSecrets {
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

    internal static func identity(_ reference: SecretRef, profile: TunnelProfile) throws -> SecretID {
        guard case let .daemonStore(id) = reference else { throw ConfigurationError.invalidSecretReference }
        let kind: SecretID.Kind = reference == profile.secrets.privateKey ? .privateKey : .presharedKey
        return SecretID(profileID: profile.id, kind: kind, id: id)
    }

    private static func references(of profile: TunnelProfile) -> [SecretRef] {
        var result = [profile.secrets.privateKey]
        for reference in Array(profile.secrets.presharedKeys.values) + Array(profile.secrets.carrierCredentials.values)
            where !result.contains(reference)
        {
            result.append(reference)
        }
        return result
    }
}
