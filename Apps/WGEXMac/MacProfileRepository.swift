// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXUI

    /// Serial app-side profile transactions. The journal contains public references only.
    @MainActor
    public final class MacProfileRepository {
        private struct Journal: Codable {
            var deleting: [TunnelProfile] = []
            var retiring: [SecretID] = []
            var failedDeletions: [TunnelProfile] = []
            /// Daemon registrations a failed save had created and could not remove at once; `reconcile` removes them.
            var unregistering: [UUID] = []

            init() {}

            init(from decoder: any Decoder) throws {
                let values = try decoder.container(keyedBy: CodingKeys.self)
                deleting = try values.decodeIfPresent([TunnelProfile].self, forKey: .deleting) ?? []
                retiring = try values.decodeIfPresent([SecretID].self, forKey: .retiring) ?? []
                failedDeletions = try values.decodeIfPresent([TunnelProfile].self, forKey: .failedDeletions) ?? []
                unregistering = try values.decodeIfPresent([UUID].self, forKey: .unregistering) ?? []
            }
        }

        private let store: ProfileStore
        private let secrets: any SecretStore
        private let installProfile: (TunnelProfile) async throws -> Void
        private let removeProfile: (UUID, Bool) async throws -> Void
        private let checkDeletion: (UUID) async throws -> Void
        private let journalURL: URL
        private var working = false
        /// An in-flight transaction owns the store until its commit or rollback finishes.
        public var isBusy: Bool {
            working
        }

        /// Supplies guarded real operations or recording test closures.
        public init(
            container: URL, store: ProfileStore, secrets: any SecretStore,
            installProfile: @escaping (TunnelProfile) async throws -> Void = { _ in },
            removeProfile: @escaping (UUID, Bool) async throws -> Void = { _, _ in },
            checkDeletion: @escaping (UUID) async throws -> Void = { _ in },
        ) {
            self.store = store; self.secrets = secrets
            self.installProfile = installProfile; self.removeProfile = removeProfile; self.checkDeletion = checkDeletion
            journalURL = container.appendingPathComponent("mac-profile-transactions.json")
        }

        /// Reuses existing account identities and retires references removed by an edit or replacement. A tunnel without an
        /// address or a server (DEC-088) is saved here only, never installed in the daemon; the first save that completes it
        /// installs it. A complete tunnel cannot be saved back to incomplete, so no stale daemon registration can remain.
        public func save(
            _ profile: TunnelProfile, secrets parsed: borrowing ParsedSecrets, previous: TunnelProfile?,
            configure: (TunnelProfile) async throws -> Void = { _ in },
        ) async throws -> TunnelProfile {
            guard !working else { throw MacWorkflowError.operationInProgress }
            working = true
            defer { working = false }
            var saved = profile
            saved.original = nil
            let keys = try prepareKeys(profile, parsed: parsed, previous: previous, saved: &saved)
            let complete = saved.isComplete
            guard complete || previous?.isComplete != true,
                  !(complete ? saved.validate() : saved.storageDiagnostics()).contains(where: { $0.severity == .error })
            else {
                throw ProfileStoreError.invalidDocument
            }
            var backups: [SecretID: MacKeyBuffer] = [:]
            var created: [SecretID] = []
            // Whether this save created the daemon registration (a new tunnel, or the first complete save of an empty one).
            var registered = false
            do {
                for (id, key) in keys {
                    if try await secrets.exists(id) {
                        backups[id] = try await MacKeyBuffer(secrets.load(id))
                        try await secrets.replace(id, with: key.copy())
                    } else {
                        try await secrets.store(key.copy(), for: id)
                        created.append(id)
                    }
                }
                try await store.save(saved)
                if complete {
                    try await installProfile(saved)
                    registered = previous?.isComplete != true
                }
                try await configure(saved)
            } catch {
                await rollBack(saved, to: previous, backups: backups, created: created, registered: registered, after: error)
                throw error
            }
            // Committed complete: a removal journalled by an earlier failed save must not undo this registration. Until now it
            // stays pending, so any failed retry keeps the clean-up; `reconcile` also skips an id whose document is complete.
            if complete {
                keepRegistration(saved.id)
            }
            let retired = Set(previous.map(Self.accounts) ?? []).subtracting(Self.accounts(saved))
            if !retired.isEmpty {
                await retireAfterCommit(retired)
            }
            return saved
        }

        /// The save has committed (document, keys and daemon registration), so it must report success: a caller that saw it
        /// fail would treat the profile as rolled back. Superseded keys are no longer referenced; one that cannot be deleted now
        /// stays in the journal and `reconcile` retires it later.
        private func retireAfterCommit(_ retired: Set<SecretID>) async {
            guard var journal = try? readJournal() else {
                for id in retired {
                    try? await deleteSecretIfPresent(id)
                }
                return
            }
            journal.retiring.append(contentsOf: retired.subtracting(journal.retiring))
            guard (try? writeJournal(journal)) != nil else {
                for id in retired {
                    try? await deleteSecretIfPresent(id)
                }
                return
            }
            do {
                try await retire(&journal)
                try writeJournal(journal)
            } catch { /* The journal keeps the remaining retirements for `reconcile`. */ }
        }

        /// The shell must refuse a possibly active profile: daemon removal can stop its tunnel.
        public func delete(_ profile: TunnelProfile) async throws {
            guard !working else { throw MacWorkflowError.operationInProgress }
            working = true
            defer { working = false }
            // A status refusal is an unaccepted deletion, not an intent to replay silently later.
            try await checkDeletion(profile.id)
            var journal = try readJournal()
            journal.failedDeletions.removeAll { $0.id == profile.id }
            if !journal.deleting.contains(where: { $0.id == profile.id }) {
                var publicProfile = profile
                publicProfile.original = nil
                journal.deleting.append(publicProfile)
                try writeJournal(journal)
            }
            try await processDeletion(profile, journal: &journal)
        }

        /// Uninstall with "Also remove tunnels and settings" (M05-T10): deletes the keys of every profile the store lists or the
        /// journal names, then the whole container (profile documents, settings, preferences and this journal). The daemon's
        /// copies are already gone, so nothing is sent to it. A retry after a failure finishes the job: missing keys and a
        /// missing container are success.
        public func removeAll() async throws {
            guard !working else { throw MacWorkflowError.operationInProgress }
            working = true
            defer { working = false }
            let container = journalURL.deletingLastPathComponent()
            guard FileManager.default.fileExists(atPath: container.path) else { return }
            // A damaged journal must not keep the listed profiles' keys behind.
            let journal = (try? readJournal()) ?? Journal()
            var ids = journal.retiring
            for profile in try await store.list() + journal.deleting + journal.failedDeletions {
                ids.append(contentsOf: Self.accounts(profile))
            }
            for id in ids {
                try await deleteSecretIfPresent(id)
            }
            try FileManager.default.removeItem(at: container)
        }

        /// Resumes interrupted deletion and secret retirement, retaining the journal on failure.
        public func reconcile() async throws {
            guard !working else { throw MacWorkflowError.operationInProgress }
            working = true
            defer { working = false }
            var journal = try readJournal()
            guard !journal.deleting.isEmpty || !journal.retiring.isEmpty || !journal.unregistering.isEmpty else { return }
            for profile in journal.deleting {
                try await processDeletion(profile, journal: &journal)
            }
            try await retire(&journal)
            try await finishUnregistering(&journal)
            try writeJournal(journal)
        }

        private func processDeletion(_ profile: TunnelProfile, journal: inout Journal) async throws {
            do { try await finishDeletion(profile) }
            catch {
                if Self.requiresExplicitRetry(error) {
                    journal.deleting.removeAll { $0.id == profile.id }
                    var publicProfile = profile
                    publicProfile.original = nil
                    journal.failedDeletions.append(publicProfile)
                    try writeJournal(journal)
                }
                throw error
            }
            journal.deleting.removeAll { $0.id == profile.id }
            try writeJournal(journal)
        }

        private static func requiresExplicitRetry(_ error: any Error) -> Bool {
            if let error = error as? MacWorkflowError, case .deletionBlocked = error {
                return true
            }
            // Flattened permission errors cannot prove a permanent denial; secure install may be repairable.
            guard let error = error as? DaemonError else { return false }
            switch error {
            case .notAuthorised(.notOwner), .notAuthorised(.noRule), .unauthorised: return true
            default: return false
            }
        }

        private func finishDeletion(_ profile: TunnelProfile) async throws {
            do { try await removeProfile(profile.id, true) }
            catch DaemonError.profileNotFound { /* The daemon may already have purged this profile. */ }
            catch TunnelError.profileNotFound { /* An interrupted deletion may already have purged the daemon. */ }
            for id in Self.accounts(profile) {
                try await deleteSecretIfPresent(id)
            }
            do { try await store.delete(profile.id) }
            catch ProfileStoreError.notFound { /* A completed file removal is idempotent on journal replay. */ }
        }

        private func retire(_ journal: inout Journal) async throws {
            for id in journal.retiring {
                try await deleteSecretIfPresent(id)
            }
            journal.retiring = []
        }

        private func deleteSecretIfPresent(_ id: SecretID) async throws {
            do { try await secrets.delete(id) }
            catch SecretStoreError.notFound { /* Secret retirement is idempotent. */ }
        }

        private func readJournal() throws -> Journal {
            guard FileManager.default.fileExists(atPath: journalURL.path) else { return Journal() }
            return try JSONDecoder().decode(Journal.self, from: Data(contentsOf: journalURL))
        }

        private func writeJournal(_ journal: Journal) throws {
            try FileManager.default.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(journal).write(to: journalURL, options: .atomic)
        }

        private static func accounts(_ profile: TunnelProfile) -> [SecretID] {
            let entries: [(SecretRef, SecretID.Kind)] = [(profile.secrets.privateKey, .privateKey)]
                + profile.secrets.presharedKeys.values.map { ($0, .presharedKey) }
                + profile.secrets.carrierCredentials.values.map { ($0, .carrierCredential) }
            return entries.compactMap { reference, kind in
                guard case let .daemonStore(id) = reference else { return nil }
                return SecretID(profileID: profile.id, kind: kind, id: id)
            }
        }

        private func prepareKeys(
            _ profile: TunnelProfile, parsed: borrowing ParsedSecrets, previous: TunnelProfile?, saved: inout TunnelProfile,
        ) throws -> [(SecretID, MacKeyBuffer)] {
            let privateID = account(
                profile.secrets.privateKey,
                previous: previous?.secrets.privateKey,
                profile: profile.id,
                kind: .privateKey,
            )
            var keys = try [(privateID, parsed.withKey(profile.secrets.privateKey) { try MacKeyBuffer(SecretBytes(copying: $0)) })]
            saved.secrets.privateKey = .daemonStore(id: privateID.id)
            for (peer, reference) in profile.secrets.presharedKeys {
                let matching = previous?.secrets.presharedKeys.values.first { $0 == reference } ?? previous?.secrets.presharedKeys[peer]
                let id = account(reference, previous: matching, profile: profile.id, kind: .presharedKey)
                try keys.append((id, parsed.withKey(reference) { try MacKeyBuffer(SecretBytes(copying: $0)) }))
                saved.secrets.presharedKeys[peer] = .daemonStore(id: id.id)
            }
            return keys
        }

        private func account(_ reference: SecretRef, previous: SecretRef?, profile: UUID, kind: SecretID.Kind) -> SecretID {
            // Reuse the existing destination identity on import replacement as well as editor saves.
            if case let .daemonStore(id) = previous {
                return SecretID(profileID: profile, kind: kind, id: id)
            }
            if case let .daemonStore(id) = reference {
                return SecretID(profileID: profile, kind: kind, id: id)
            }
            return SecretID(profileID: profile, kind: kind)
        }
    }

    /// Rollback of a failed save, including a daemon registration the save created (DEC-088: the first complete save of an
    /// empty tunnel, or a new tunnel), with a journalled retry when the daemon refuses the removal.
    extension MacProfileRepository {
        /// Restores the keys, the document and the daemon state a failed save replaced: the previous complete tunnel's
        /// registration is installed again, and a registration this save created is removed (journalled for `reconcile` when
        /// that fails). After a revision conflict the daemon holds a revision this save did not write, so it is left alone.
        private func rollBack(
            _ saved: TunnelProfile, to previous: TunnelProfile?, backups: [SecretID: MacKeyBuffer], created: [SecretID],
            registered: Bool, after error: any Error,
        ) async {
            for (id, backup) in backups {
                try? await secrets.replace(id, with: backup.copy())
            }
            for id in created {
                try? await secrets.delete(id)
            }
            if let previous {
                try? await store.save(previous)
            } else {
                try? await store.delete(saved.id)
            }
            guard (error as? TunnelError) != .revisionConflict, (error as? DaemonError) != .tunnel(.revisionConflict) else { return }
            if registered {
                await unregister(saved.id)
            } else if let previous, previous.isComplete {
                try? await installProfile(previous)
            }
        }

        /// Removes a registration a failed save created; when the daemon refuses now (it is unreachable, or a tunnel is up),
        /// the journal keeps the id and `reconcile` retries.
        private func unregister(_ id: UUID) async {
            do { try await removeRegistration(id) }
            catch {
                guard var journal = try? readJournal() else { return }
                if !journal.unregistering.contains(id) {
                    journal.unregistering.append(id)
                }
                try? writeJournal(journal)
            }
        }

        private func removeRegistration(_ id: UUID) async throws {
            do { try await removeProfile(id, true) }
            catch DaemonError.profileNotFound { /* Nothing registered: done. */ }
            catch TunnelError.profileNotFound { /* Nothing registered: done. */ }
        }

        /// A committed complete save registered the tunnel on purpose, so a pending removal from an earlier failed save is
        /// dropped. Best effort: when the journal cannot be written, `reconcile` finds the complete document and drops it then.
        private func keepRegistration(_ id: UUID) {
            guard FileManager.default.fileExists(atPath: journalURL.path), var journal = try? readJournal(),
                  journal.unregistering.contains(id) else { return }
            journal.unregistering.removeAll { $0 == id }
            try? writeJournal(journal)
        }

        /// Removes the registrations failed saves left behind, unless the tunnel has since been saved complete (and so
        /// registered on purpose); the journal keeps any the daemon still refuses.
        private func finishUnregistering(_ journal: inout Journal) async throws {
            for id in journal.unregistering {
                if let document = try? await store.load(id), document.isComplete {
                    journal.unregistering.removeAll { $0 == id }
                    continue
                }
                do { try await removeRegistration(id) }
                catch {
                    try writeJournal(journal)
                    throw error
                }
                journal.unregistering.removeAll { $0 == id }
            }
        }
    }
#endif
