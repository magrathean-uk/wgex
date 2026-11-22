// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import WGEXCore
import WGEXProfileStore

/// Confined to a single commit. Rollback buffers remain uniquely owned and are wiped on release.
internal final class SecretTransaction {
    private final class Backup {
        let bytes: SecretBytes
        init(_ bytes: consuming SecretBytes) {
            self.bytes = bytes
        }
    }

    private let strategy: ProfileComposition.Strategy
    private var added: [SecretID] = []
    private var backups: [SecretID: Backup] = [:]

    internal init(strategy: ProfileComposition.Strategy) {
        self.strategy = strategy
    }

    internal func store(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets) async throws -> TunnelProfile {
        var saved = profile
        do {
            switch strategy {
            case .persistentReferences:
                saved.original = nil // Original placeholders refer to the unsealed references.
                saved.secrets.privateKey = try await write(profile.secrets.privateKey, profile: profile, secrets: secrets)
                for (peer, reference) in profile.secrets.presharedKeys {
                    saved.secrets.presharedKeys[peer] = try await write(reference, profile: profile, secrets: secrets)
                }
            case .identities:
                for reference in secrets.references.keys {
                    _ = try await write(reference, profile: profile, secrets: secrets)
                }
            }
        } catch {
            await rollback()
            throw error
        }
        return saved
    }

    internal func rollback() async {
        let store: any SecretStore = switch strategy {
        case let .persistentReferences(store): store
        case let .identities(store): store
        }
        for id in added {
            try? await store.delete(id)
        }
        for (id, backup) in backups {
            if let copy = try? SecretBytes(parsing: backup.bytes) {
                try? await store.replace(id, with: copy)
            }
        }
    }

    private func write(
        _ reference: SecretRef, profile: TunnelProfile, secrets: borrowing ParsedSecrets,
    ) async throws -> SecretRef {
        var bytes = try SecretBytes(zeroedCount: 32)
        try secrets.withKey(reference) { source in
            bytes.withUnsafeMutableBytes { $0.copyMemory(from: source) }
        }
        switch strategy {
        case let .persistentReferences(store):
            let kind: SecretID.Kind = reference == profile.secrets.privateKey ? .privateKey : .presharedKey
            let id = SecretID(profileID: profile.id, kind: kind)
            try await store.store(bytes, for: id)
            added.append(id)
            return try await .keychain(persistentRef: store.persistentReference(for: id))
        case let .identities(store):
            let id = try ProfileComposition.identity(reference, profile: profile)
            if try await store.exists(id) {
                backups[id] = try await Backup(store.load(id))
                try await store.replace(id, with: bytes)
            } else {
                try await store.store(bytes, for: id)
                added.append(id)
            }
            return reference
        }
    }
}
