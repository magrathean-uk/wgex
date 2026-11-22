// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXProfileStore
    import WGEXUI

    // MARK: - Editor and export

    public extension MacAppModel {
        /// Create Empty Tunnel (SPEC 6.1, DEC-088): the editor opens on a new tunnel with a generated key pair, as the official
        /// app does; a name and Save store it, and a missing address or server blocks only activation.
        func openNewProfile() {
            let editor = ProfileEditorModel(featureFlags: shell.preferences.flags, allowsIncomplete: true)
            editor.generateKeypair()
            // The generated pair is the new tunnel's starting point, not an edit: Cancel closes without asking.
            editor.markSaved()
            self.editor = editor
        }

        func openEditor() {
            guard let profile = shell.selectedProfile else { return }
            Task {
                do {
                    let secrets = try await storedSecrets(profile)
                    editor = try ProfileEditorModel(
                        profile: profile, secrets: secrets, featureFlags: shell.preferences.flags, allowsIncomplete: true,
                    )
                } catch { shell.reportError(error) }
            }
        }

        func closeEditor() {
            editor = nil
        }

        func closeExport() {
            exportModel?.cancel(); exportModel = nil
        }

        /// Saves public fields, startup policy and all keys before the editor marks the draft saved. The active profile is edited
        /// as the official app's `modify` does: the save commits first (a save that fails half-way rolls back to the old profile,
        /// still running), then a changed tunnel is restarted in place. Startup options of another profile wait for an idle tunnel.
        func saveEditor(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets) async throws {
            guard !shell.hostGuarded else { throw ServiceError.hostGuard }
            let previous = shell.profiles.first { $0.id == profile.id }
            let option = MacStartupOption(options: profile.macOptions)
            // An incomplete tunnel has nothing to start or arm (DEC-088); the editor already refuses these choices.
            guard shell.canActivate(profile) || (option == .off && !shell.isOnDemandConfigured(profile)) else {
                throw ConfigValidationError(diagnostics: [
                    ConfigDiagnostic(severity: .error, code: .unsupportedSetting, message: MacStrings.incompleteTunnelOptions),
                ])
            }
            let running = shell.isRunningTunnel(profile.id)
            if (previous?.macOptions ?? MacProfileOptions()) != profile.macOptions {
                guard shell.status.phase == .idle || running else { throw TunnelError.anotherTunnelActive }
                try shell.checkStartup(option)
            }
            let keysChanged = running ? await keysDiffer(previous, from: secrets) : false
            let armed = running && shell.isOnDemandArmed(profile.id)
            do {
                var restarts = false
                let saved = try await repository.save(profile, secrets: secrets, previous: previous) { saved in
                    // The daemon takes the edit before startup changes, which roll themselves back if they fail.
                    restarts = running && (keysChanged || Self.tunnelChanged(from: previous, to: saved))
                    if restarts {
                        try await self.shell.installRunningEdit(saved)
                    }
                    if previous?.macOptions != saved.macOptions {
                        var startupProfile = saved
                        startupProfile.macOptions = previous?.macOptions ?? MacProfileOptions()
                        try await self.shell.persistStartup(startupProfile, option: option)
                    }
                }
                if let index = shell.profiles.firstIndex(where: { $0.id == saved.id }) {
                    shell.profiles[index] = saved
                } else {
                    shell.profiles.append(saved)
                    shell.selectedProfileID = saved.id
                }
                // An edit of the open tunnel keeps the window on it.
                if shell.selectedProfileID == saved.id {
                    shell.selectByAction(saved.id)
                }
                editor = nil
                if restarts {
                    await shell.restartRunningTunnel(saved, rearming: armed)
                }
                await onDemandAfterSave(saved, previous: previous)
            } catch { shell.reportError(error); throw error }
        }

        /// Whether a saved profile runs differently: the official app restarts when its tunnel configuration changed, which
        /// excludes on-demand rules. WGEX also leaves out what the running tunnel never reads (name, startup, retained text).
        static func tunnelChanged(from previous: TunnelProfile?, to saved: TunnelProfile) -> Bool {
            guard let previous else { return true }
            return previous.interface != saved.interface || previous.peers != saved.peers || previous.secrets != saved.secrets
                || previous.transport != saved.transport || previous.protection != saved.protection
        }

        /// Whether the editor's keys differ from the stored ones under the same references; unreadable counts as changed.
        // swiftformat:disable:next redundantInternal
        internal func keysDiffer(_ previous: TunnelProfile?, from secrets: borrowing ParsedSecrets) async -> Bool {
            guard let previous, let stored = try? await storedSecrets(previous),
                  Set(stored.references.keys) == Set(secrets.references.keys) else { return true }
            for reference in secrets.references.keys {
                let same = try? secrets.withKey(reference) { new in
                    try stored.withKey(reference) { old in new.elementsEqual(old) }
                }
                guard same == true else { return true }
            }
            return false
        }

        /// ADR-030 sections 3 and 6: a rule that lists networks asks for Location now; a rule introduced on a profile that is
        /// up arms it, as the official app's `modify` does. The save itself has already succeeded, so a refusal only reports.
        func onDemandAfterSave(_ saved: TunnelProfile, previous: TunnelProfile?) async {
            onDemandRelay?.profileWillBeSavedOrArmed(saved)
            guard shell.activeProfileID == saved.id, shell.isOnDemandConfigured(saved), !shell.isOnDemandArmed(saved.id),
                  !(previous.map(shell.isOnDemandConfigured) ?? false) else { return }
            await shell.setOnDemand(true, for: saved)
        }

        /// The connected Wi-Fi network for the editor's "Add connected network"; asks for Location when undecided.
        func connectedNetwork() async -> ConnectedNetworkReading {
            await onDemandRelay?.connectedNetwork() ?? .notAssociated
        }

        func openExport() {
            guard let profile = shell.selectedProfile else { return }
            Task {
                do {
                    let secrets = try await storedSecrets(profile)
                    exportModel = ExportModel(profile: profile, secrets: secrets)
                } catch { shell.reportError(error) }
            }
        }

        // swiftformat:disable:next redundantInternal
        internal func storedSecrets(_ profile: TunnelProfile) async throws -> ParsedSecrets {
            let entries: [(SecretRef, SecretID.Kind)] = [(profile.secrets.privateKey, .privateKey)]
                + profile.secrets.presharedKeys.values.map { ($0, .presharedKey) }
            var bytes = try SecretBytes(zeroedCount: entries.count * 32)
            var references: [SecretRef: Range<Int>] = [:]
            for (index, entry) in entries.enumerated() {
                guard case let .daemonStore(id) = entry.0 else { throw SecretStoreError.unavailable }
                let key = try await secretStore.load(SecretID(profileID: profile.id, kind: entry.1, id: id))
                try key.copyBytes(into: &bytes, at: index * 32)
                references[entry.0] = (index * 32) ..< (index * 32 + 32)
            }
            return try ParsedSecrets(bytes: bytes, references: references)
        }
    }

    public extension MacAppModel {
        @discardableResult
        func confirmImport(
            _ profile: TunnelProfile, secrets: borrowing ParsedSecrets, connect: Bool, replacing: UUID?,
        ) throws -> Task<Void, Never> {
            guard !shell.hostGuarded else { throw ServiceError.hostGuard }
            guard shell.canSelectProfile, !importSaving else { throw MacWorkflowError.operationInProgress }
            // Replacing the running profile saves the new configuration, then restarts it in place like an edit.
            let running = replacing.map(shell.isRunningTunnel) ?? false
            let armed = running && replacing.map(shell.isOnDemandArmed) == true
            let previous = shell.profiles.first { $0.id == (replacing ?? profile.id) }
            var saved = importedProfile(profile, replacing: replacing, keepingRulesOf: running ? previous : nil)
            let packed = try MacImportKeyPack(profile: profile, secrets: secrets)
            importSaving = true
            importErrorMessage = nil
            return Task {
                defer { importSaving = false }
                do {
                    let secrets = try packed.secrets()
                    saved = try await repository.save(saved, secrets: secrets, previous: previous) { saved in
                        if running {
                            try await self.shell.installRunningEdit(saved)
                        }
                    }
                    if let index = shell.profiles.firstIndex(where: { $0.id == saved.id }) {
                        shell.profiles[index] = saved
                    } else {
                        shell.profiles.append(saved)
                    }
                    shell.selectByAction(saved.id)
                    if !importReviews.isEmpty {
                        importReviews.removeFirst()
                    }
                    for review in importReviews {
                        review.existingProfiles = shell.profiles
                    }
                    if importReviews.isEmpty {
                        importing = false
                    }
                    if running {
                        await shell.restartRunningTunnel(saved, rearming: armed)
                    } else if connect {
                        await shell.toggleConnection()
                    }
                } catch {
                    importErrorMessage = MacAppErrorCopy.resolve(error).message
                    shell.reportError(error)
                }
            }
        }

        /// Add All (SPEC 6.2): saves every reviewed configuration without errors under a unique name, one after another; the
        /// ones with errors are left out (the list names them). Keys are copied out of each review before the first save. Each
        /// review leaves the list as soon as its tunnel is saved, so after a failure a second Add All retries only what failed;
        /// a review whose tunnel is already in the list is never saved again. `only` limits the saves to the ticked reviews
        /// (DEC-110 item 21); once every ticked one is saved the sheet closes and the unticked ones are dropped.
        @discardableResult
        func confirmAllImports(only selected: [ImportReviewModel]? = nil) -> Task<Void, Never>? {
            guard !shell.hostGuarded else { shell.reportError(ServiceError.hostGuard); return nil }
            guard shell.canSelectProfile, !importSaving else { return nil }
            var staged: [(ImportReviewModel, TunnelProfile, MacImportKeyPack)] = []
            var known = shell.profiles
            let chosen = importReviews.filter { review in selected?.contains { $0 === review } ?? true }
            for review in chosen where review.canImport && !shell.profiles.contains(where: { $0.id == review.profile.id }) {
                review.confirm { profile, secrets in
                    var profile = profile
                    profile.name = MacImportNaming.unique(profile.name, among: known)
                    let saved = importedProfile(profile, replacing: nil, keepingRulesOf: nil)
                    try staged.append((review, saved, MacImportKeyPack(profile: profile, secrets: secrets)))
                    known.append(saved)
                }
            }
            guard !staged.isEmpty else { return nil }
            importSaving = true
            importErrorMessage = nil
            return Task {
                defer { importSaving = false }
                for (review, profile, pack) in staged {
                    do {
                        let secrets = try pack.secrets()
                        let saved = try await repository.save(profile, secrets: secrets, previous: nil)
                        if let index = shell.profiles.firstIndex(where: { $0.id == saved.id }) {
                            shell.profiles[index] = saved
                        } else {
                            shell.profiles.append(saved)
                        }
                        shell.selectByAction(saved.id)
                        importReviews.removeAll { $0 === review }
                    } catch {
                        importErrorMessage = MacAppErrorCopy.resolve(error).message
                        shell.reportError(error)
                    }
                }
                for review in importReviews {
                    review.existingProfiles = shell.profiles
                }
                // Only reviews with errors or unticked ones left: the list named them and they are not added.
                if !importReviews.contains(where: { review in review.canImport && chosen.contains { $0 === review } }) {
                    importReviews = []
                    importing = false
                }
            }
        }

        /// The profile an import saves, under the id of the profile it replaces. On-demand rules are not part of the official
        /// app's tunnel configuration, so its `modify` keeps them: a file without rules that replaces the running profile keeps
        /// that profile's rules, and an armed profile stays armed across the restart. A file carries no startup options and an
        /// import never runs the startup transaction, so the replaced profile's options are kept: the saved document then
        /// agrees with the login item and the daemon's boot intent, which the replacement leaves as they were.
        // swiftformat:disable:next redundantInternal
        internal func importedProfile(
            _ profile: TunnelProfile, replacing: UUID?, keepingRulesOf running: TunnelProfile?,
        ) -> TunnelProfile {
            let replaced = replacing.flatMap { id in shell.profiles.first { $0.id == id } }
            var saved = profile.importedCopy(id: replacing ?? profile.id, macOptions: replaced?.macOptions ?? profile.macOptions)
            if let running, !shell.isOnDemandConfigured(saved) {
                saved.onDemand = running.onDemand
            }
            return saved
        }

        /// Disk refreshes preserve edits, imports and removals committed while the read was suspended.
        static func mergeProfiles(loaded: [TunnelProfile], baseline: [TunnelProfile], current: [TunnelProfile]) -> [TunnelProfile] {
            let before = Dictionary(baseline.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
            let disk = Dictionary(loaded.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
            let currentIDs = Set(current.map(\.id))
            return current.compactMap { profile in
                if before[profile.id] != profile {
                    return profile
                }
                return disk[profile.id]
            } + loaded.filter { !currentIDs.contains($0.id) && before[$0.id] == nil }
        }
    }

#endif
