// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    public extension MacShellModel {
        /// Refreshes registration on activation, including the return from System Settings.
        func applicationActivated() async {
            guard !hostGuarded else { return }
            await refreshService()
        }

        /// Uses the same real secure-install operation from setup, Settings and the main card.
        func verifySecureInstall() async {
            guard serviceState == .enabled, daemonRunning else {
                operationMessage = MacStrings.approveAndStartTheBackground
                return
            }
            let previous = secureInstall
            await perform {
                self.secureInstall = .checking
                do {
                    self.secureInstall = try await self.operations.secureInstall()
                } catch TunnelError.cancelled {
                    self.secureInstall = previous
                    self.operationMessage = MacErrorCopy(.secureCancelled).message
                    return
                } catch {
                    self.secureInstall = previous
                    throw error
                }
                if self.secureInstall == .verified {
                    await self.completeOnboarding()
                }
            }
        }

        /// Replaces the cache only with the daemon's acknowledged settings.
        func setGlobalSettings(_ settings: MacGlobalSettings) async {
            guard !hostGuarded else { reportError(ServiceError.hostGuard); return }
            await perform {
                self.preferences.global = try await self.operations.setGlobalSettings(settings)
            }
        }

        /// A Settings control edits a proposal rather than the daemon-backed preference cache.
        func globalSetting<Value>(_ key: WritableKeyPath<MacGlobalSettings, Value>) -> Binding<Value> {
            Binding(get: { self.preferences.global[keyPath: key] }, set: { value in
                var proposal = self.preferences.global
                proposal[keyPath: key] = value
                Task { await self.setGlobalSettings(proposal) }
            })
        }

        /// Guard shared by the settings picker and the editor's startup controls.
        func checkStartup(_ option: MacStartupOption) throws {
            guard !hostGuarded else { throw ServiceError.hostGuard }
            guard option != .boot || (secureInstall == .verified && daemonRunning) else {
                operationMessage = MacStrings.completeSecureInstallBefore
                throw MacWorkflowError.secureInstallRequired
            }
        }

        /// Commits startup for an explicit profile; the editor need not change sidebar selection.
        func persistStartup(_ profile: TunnelProfile, option: MacStartupOption) async throws {
            guard option != MacStartupOption(options: profile.macOptions) else { return }
            try checkStartup(option)
            try await operations.saveStartup(profile, option)
        }

        /// Commits an exclusive off/login/boot choice before updating the profile cache.
        func saveStartup(_ option: MacStartupOption) async {
            guard let profile = selectedProfile else { operationMessage = MacStrings.addAProfileBeforeChoosingA; return }
            guard option != MacStartupOption(options: profile.macOptions) else { return }
            // DEC-088: a tunnel without an address or a server has nothing to start at login or boot.
            guard option == .off || canActivate(profile) else { operationMessage = MacStrings.incompleteTunnelOptions; return }
            do { try checkStartup(option) } catch { return }
            await perform {
                try await self.persistStartup(profile, option: option)
                if let index = self.profiles.firstIndex(where: { $0.id == profile.id }) {
                    self.profiles[index].macOptions = option.profileOptions
                }
            }
        }

        /// Completes setup durably: on step 2 Continue, and when secure install verifies from Background Service.
        func completeOnboarding() async {
            preferences.onboardingComplete = true
            if let flushPreferences {
                await flushPreferences()
            } else {
                await savePreferences()
            }
        }

        /// Step 1 Continue enters step 2 and registers the background service there; step 2 Continue completes setup with
        /// an immediate write (the only real gate has passed, so a quit at step 3 does not rerun setup) and shows step 3.
        func advanceOnboarding() async {
            guard canAdvance else { return }
            switch onboardingStep {
            case .welcome:
                onboardingStep = .backgroundService
                await enterBackgroundServiceStep()
            case .backgroundService:
                await completeOnboarding()
                onboardingStep = .addTunnel
            case .addTunnel: break
            }
        }

        /// macOS only asks for approval once the service is registered and setup has no Register button (SPEC 7), so
        /// entering step 2 registers it: once, only when the fresh state says it is not registered, never under the host guard.
        func enterBackgroundServiceStep() async {
            setupRegistrationFailed = false
            guard !hostGuarded else { return }
            await refreshService()
            guard onboardingStep == .backgroundService, serviceState == .notRegistered else { return }
            await registerFromSetup()
        }

        /// Step 2's Register Again, shown after a failed registration or when macOS cannot find the service.
        func registerFromSetup() async {
            await registerService()
            setupRegistrationFailed = serviceState == .notRegistered || serviceState == .notFound
        }

        /// Step 2 offers Register Again only after macOS refused the registration or cannot find the service.
        var setupOffersRegisterAgain: Bool {
            guard !hostGuarded else { return false }
            return serviceState == .notFound || (serviceState == .notRegistered && setupRegistrationFailed)
        }

        /// Step 2's one plain line under the Background service row, if anything stops the service.
        var setupServiceProblem: String? {
            if hostGuarded {
                return MacShellCopy.hostGuard
            }
            switch serviceState {
            case .notFound: return MacStrings.backgroundServiceNotFound
            case .notRegistered where setupRegistrationFailed && !busy: return MacStrings.backgroundServiceNotRegistered
            default: return nil
            }
        }

        /// Deletes a tunnel (SPEC 6.4). The active tunnel is deactivated first and the delete waits, bounded, for an idle status;
        /// a failed or unfinished deactivation deletes nothing and says why. `MacProfileDeletionPolicy` then refuses a live
        /// generation (another tunnel is up) or a blocking failure, and the repository rechecks the daemon's status.
        func deleteProfile(_ profile: TunnelProfile, idleWait: MacIdleWait = .standard) async {
            guard !hostGuarded else { reportError(ServiceError.hostGuard); return }
            // Another command (an Activate in flight, a save) owns the shell: say so instead of returning silently.
            guard !busy else {
                let busyCopy = operations.errorCopy(MacWorkflowError.operationInProgress).message
                operationMessage = deletionDeactivatesFirst(profile)
                    ? MacStrings.tunnelNotDeletedNotDeactivated(profile.name, reason: busyCopy) : busyCopy
                return
            }
            if deletionDeactivatesFirst(profile) {
                guard await deactivateBeforeDeletion(profile, wait: idleWait) else { return }
            }
            guard MacProfileDeletionPolicy.canDelete(status) else {
                operationMessage = MacErrorCopy(.deletionBlocked).message
                return
            }
            await perform {
                try await self.operations.deleteProfile(profile)
                self.profiles.removeAll { $0.id == profile.id }
                if self.selectedProfileID == profile.id {
                    self.selectedProfileID = self.profiles.first?.id
                }
            }
        }

        /// Stops the tunnel being deleted (an armed one is disarmed, which also stops it) and waits for the service to report
        /// it idle. False, with the reason in `operationMessage`, when it could not be stopped in time.
        private func deactivateBeforeDeletion(_ profile: TunnelProfile, wait: MacIdleWait) async -> Bool {
            busy = true
            operationMessage = nil
            requestedProfileID = nil
            pendingAction = .disconnecting
            defer { pendingAction = nil; busy = false }
            do {
                if isOnDemandArmed(profile.id) {
                    try await operations.disarmOnDemand(profile.id)
                }
                if status.phase.generation != nil || connectionRequestInFlight {
                    if let stop = daemonHooks.stopCurrent {
                        try await stop()
                    } else {
                        try await backend.stop(profile.id)
                    }
                }
            } catch {
                operationMessage = MacStrings.tunnelNotDeletedNotDeactivated(profile.name, reason: operations.errorCopy(error).message)
                return false
            }
            for attempt in 0 ..< wait.attempts {
                await refreshStatusForDeletion()
                if status.phase.generation == nil {
                    return true
                }
                if attempt + 1 < wait.attempts {
                    try? await wait.pause()
                }
            }
            operationMessage = MacStrings.tunnelNotDeletedNotDeactivated(profile.name, reason: nil)
            return false
        }

        /// One fresh status read: the service's measured report, or the preview backend's current status.
        private func refreshStatusForDeletion() async {
            if let refresh = daemonHooks.refreshStatus {
                try? await refresh()
            } else if simulated {
                for await update in backend.statusUpdates() {
                    receive(update, at: Date()); break
                }
            }
        }

        /// Resolves every error through the typed table; no raw payload enters UI copy.
        func reportError(_ error: any Error) {
            if (error as? TunnelError) == .serviceRecovering {
                operationMessage = MacErrorCopy(.serviceRecovering, protection: status.protection).message
            } else {
                operationMessage = operations.errorCopy(error).message
            }
        }

        /// Paste from Clipboard found no WireGuard configuration and no Add sheet is open to say so (SPEC 6.1).
        func reportClipboardWithoutConfiguration() {
            operationMessage = MacStrings.clipboardHoldsNoConfiguration
        }

        /// Reports quarantined documents once per store instance without disclosing file contents.
        func reportQuarantinedProfiles() {
            operationMessage = MacStrings.quarantinedProfiles
        }
    }

    /// How long a delete waits for the deactivated tunnel to report idle: `attempts` status reads, `pause` between them.
    public nonisolated struct MacIdleWait: Sendable {
        public let attempts: Int
        public let pause: @Sendable () async throws -> Void

        public init(attempts: Int, pause: @escaping @Sendable () async throws -> Void) {
            self.attempts = max(1, attempts); self.pause = pause
        }

        /// About ten seconds: forty reads a quarter of a second apart.
        public static let standard = MacIdleWait(attempts: 40) { try await Task.sleep(for: .milliseconds(250)) }
    }

    /// A terminal, non-blocking failure has no live generation and may be deleted like idle state.
    public nonisolated enum MacProfileDeletionPolicy {
        public static func canDelete(_ phase: TunnelPhase) -> Bool {
            guard phase.generation == nil else { return false }
            if case .failed(_, blockedByPolicy: true, needsSecrets: _) = phase {
                return false
            }
            return true
        }

        /// Recovery explicitly admits owner-authorised registration repair; the daemon rechecks ownership.
        public static func canDelete(_ status: TunnelStatus) -> Bool {
            status.recoveryFailureReason != nil || canDelete(status.phase)
        }

        /// Applies the status-aware guard before the repository starts its ordered deletion transaction.
        public static func check(_ status: TunnelStatus) throws(MacWorkflowError) {
            guard canDelete(status) else { throw .deletionBlocked }
        }

        public static func check(_ phase: TunnelPhase) throws(MacWorkflowError) {
            guard canDelete(phase) else { throw .deletionBlocked }
        }
    }
#endif
