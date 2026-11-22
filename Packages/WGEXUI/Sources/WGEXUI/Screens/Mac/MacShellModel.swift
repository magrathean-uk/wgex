// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Observation
    import os
    import WGEXCore

    /// Shared state for the menu, main window, Settings and onboarding. No platform mutations.
    @MainActor @Observable
    public final class MacShellModel {
        /// A compatible older daemon needs an explicitly authorised update.
        /// A compatible older daemon can be replaced through the explicit update action.
        public internal(set) var updateAvailable = false
        public private(set) var traffic = MacSessionTraffic()
        public var profiles: [TunnelProfile]
        public var selectedProfileID: UUID?
        /// The user picked a tunnel in the sidebar; later window opens keep it instead of the SPEC 5.1 destination.
        public internal(set) var tunnelChosen = false
        /// The first daemon report has applied the SPEC 5.1 destination, so the active tunnel is known.
        @ObservationIgnored package var initialReportApplied = false
        /// The selection the SPEC 5.1 rule last made; any other selection (sidebar, selectByAction) is kept.
        @ObservationIgnored package var ruleSelectedProfileID: UUID?
        public private(set) var activeProfileID: UUID?
        public var preferences: MacPreferences
        public var settingsTab: MacSettingsTab = .general
        public var showsSettings = false
        public var showsOnboarding = false
        public var onboardingStep: MacOnboardingStep = .welcome
        /// Setup step 2 tried to register the background service and macOS left it unregistered or could not find it.
        public internal(set) var setupRegistrationFailed = false
        public private(set) var status: TunnelStatus
        public private(set) var serviceState: ServiceState = .notRegistered
        public private(set) var daemonRunning = false
        public private(set) var daemonConnection: MacDaemonConnectionState = .disconnected(lastError: nil)
        public internal(set) var secureInstall: SecureInstallState = .notReporting
        /// Registration progress, independent of measured protection.
        public internal(set) var updateHandoff: MacUpdateHandoffState = .idle
        public private(set) var downgradeDetected = false
        public internal(set) var operationMessage: String?
        public internal(set) var busy = false
        /// The control command awaiting the daemon's acknowledgement, if any (DEC-008 serialises them).
        public internal(set) var pendingAction: MacPendingAction?
        package var connectionRequestInFlight = false
        public private(set) var lastStatusAt: Date?
        /// Daemon measurement time retained for last-known evidence when reachability clears the freshness timestamp.
        public private(set) var lastReceivedReportAt: Date?
        public private(set) var statistics: TunnelStatistics?
        public private(set) var now: Date
        public let simulated: Bool
        public let hostGuarded: Bool
        /// App adapters for measured refresh, cancellation, approval and visibility.
        @ObservationIgnored public var daemonHooks = MacDaemonHooks()
        @ObservationIgnored package var secureInstallTask: Task<Void, Never>?
        @ObservationIgnored package var connectionRevision = 0
        @ObservationIgnored package var requestedProfileID: UUID?
        @ObservationIgnored package let backend: any TunnelBackend
        /// Service adapter shared with the application update handoff.
        @ObservationIgnored public let service: any ServiceControlling
        @ObservationIgnored package let operations: MacShellOperations
        @ObservationIgnored package var flushPreferences: (() async -> Void)?
        /// The uninstall sequence shared by Settings > Service and the launch offer to finish one (M05-T10).
        public let uninstall: MacUninstall
        /// DEC-088: tunnels saved without an address or a server cannot be activated, armed or chosen for start-up. The Mac app
        /// turns this on with the store opt-in that admits such tunnels; shell fixtures and previews that never save leave it off.
        public var refusesIncompleteTunnels = false

        public init(
            dependencies: MacShellDependencies,
            profiles: [TunnelProfile] = [],
            preferences: MacPreferences = MacPreferences(),
            status: TunnelStatus? = nil,
            now: Date = Date(),
        ) {
            backend = dependencies.backend; service = dependencies.service
            operations = dependencies.operations
            uninstall = MacUninstall(operations: dependencies.operations)
            simulated = dependencies.simulated; hostGuarded = dependencies.hostGuarded
            self.profiles = profiles
            selectedProfileID = profiles.first?.id
            activeProfileID = status?.activeProfileID
            self.preferences = preferences
            self.now = now
            self.status = status ?? TunnelStatus(phase: .idle, protection: .unknown, transport: nil, health: .idle, recentEvents: [])
            lastStatusAt = status?.measuredAt ?? (dependencies.simulated && status != nil ? now : nil)
            lastReceivedReportAt = lastStatusAt
        }

        public var selectedProfile: TunnelProfile? {
            profiles.first { $0.id == selectedProfileID }
        }

        public var startupOption: MacStartupOption {
            selectedProfile.map { MacStartupOption(options: $0.macOptions) } ?? .off
        }

        /// Called by the app's single observation owner, never by each transient menu window.
        public func observeTunnel() async {
            for await update in backend.statusUpdates() {
                guard !Task.isCancelled else { return }
                receive(update, at: Date())
            }
            #if WGEX_LAB_BUILD
                Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "app").log("observeTunnel ended")
            #endif
            lastStatusAt = nil
        }

        public func observeService() async {
            for await update in service.state {
                guard !Task.isCancelled else { return }
                receiveService(update)
            }
            daemonRunning = false
        }

        public func receive(_ update: TunnelStatus, at date: Date) {
            if case .idle = update.phase, update.protection == .unprotected {
                traffic = MacSessionTraffic()
                statistics = nil
                activeProfileID = nil
            }
            activeProfileID = update.activeProfileID
            if simulated, update.phase.generation != nil, activeProfileID == nil {
                activeProfileID = requestedProfileID ?? selectedProfileID
            }
            status = update
            now = date
            applyInitialTunnelOnFirstReport(update)
            lastStatusAt = update.measuredAt ?? (simulated ? date : nil)
            if let measuredAt = update.measuredAt ?? update.lastReportedAt {
                lastReceivedReportAt = measuredAt
            } else if simulated {
                lastReceivedReportAt = date
            }
        }

        public func tick(at date: Date) {
            now = date
        }

        public func closeExpiredCaptiveWindow() async {
            guard simulated, case let .captiveWindow(expires) = status.protection, now >= expires else { return }
            await closeCaptiveWindow()
        }

        public func dismissMessage() {
            operationMessage = nil
        }

        public func receiveService(_ update: ServiceState) {
            serviceState = update
            if update != .enabled {
                if simulated {
                    daemonRunning = false
                }
                secureInstall = .notReporting
            }
        }

        public func toggleConnection() async {
            guard !hostGuarded else { return }
            // A profile with an on-demand rule arms and disarms (ADR-030 section 6 rule 1) instead of starting by hand.
            if await performOnDemandControl(windowPrimaryControl) {
                return
            }
            switch detailPresentation.action {
            case .disconnect, .cancel: await disconnectActiveProfile()
            case .checkAgain: await checkStatusAgain()
            case .endCaptiveWindow: await closeCaptiveWindow()
            case .connect, .reconnect: await startSelectedProfile()
            }
        }

        private func disconnectActiveProfile() async {
            requestedProfileID = nil
            pendingAction = .disconnecting
            defer { pendingAction = nil }
            do {
                try await stopActiveProfile()
            } catch { reportError(error) }
        }

        private func checkStatusAgain() async {
            do {
                if let refresh = daemonHooks.refreshStatus {
                    try await refresh()
                } else if simulated {
                    for await update in backend.statusUpdates() {
                        receive(update, at: Date()); break
                    }
                }
            } catch { reportError(error) }
        }

        private func stopActiveProfile() async throws {
            if let stop = daemonHooks.stopCurrent {
                try await stop()
            } else if let id = activeProfileID ?? selectedProfileID {
                try await backend.stop(id)
            }
        }

        private func startSelectedProfile(fromMenu: Bool = false) async {
            // DEC-088: an incomplete tunnel is never sent to the daemon; the menu and window say why instead.
            guard !busy, let profile = selectedProfile, admitsActivation(profile), fromMenu || canConnect else { return }
            connectionRequestInFlight = true
            pendingAction = .connecting(profile.id)
            defer { connectionRequestInFlight = false; pendingAction = nil }
            await perform {
                self.requestedProfileID = profile.id
                if let active = self.activeProfileID, active != profile.id {
                    if let stop = self.daemonHooks.stopCurrent {
                        try await stop()
                    } else {
                        try await self.backend.stop(active)
                    }
                }
                try await self.backend.install(profile)
                // Cancel may have arrived while installation was awaiting XPC.
                guard self.requestedProfileID == profile.id else { return }
                try await self.backend.start(profile.id, transport: nil)
            }
        }

        public func registerService() async {
            guard !hostGuarded else { operationMessage = MacShellCopy.hostGuard; return }
            await perform {
                // The controller reconciles SMAppService throws with pending approval;
                // a successful registration leaves the error toast clear.
                try await self.service.register()
                await self.refreshService()
            }
        }

        public func reregisterService() async {
            guard !hostGuarded else { operationMessage = MacShellCopy.hostGuard; return }
            await perform {
                try await self.service.unregister()
                self.receiveService(.notRegistered)
                try await self.service.register()
                await self.refreshService()
            }
        }

        public func openApproval() {
            guard !hostGuarded else { operationMessage = MacShellCopy.hostGuard; return }
            service.openApproval()
        }

        public func refreshService() async {
            guard !hostGuarded else { operationMessage = MacShellCopy.hostGuard; return }
            daemonHooks.refreshServiceApproval?()
            for await update in service.state {
                receiveService(update); break
            }
            guard serviceState == .enabled else { return }
            do { daemonRunning = try await operations.refreshDaemon() }
            catch {
                daemonRunning = false
                reportError(error)
            }
        }

        public func reportSecureInstallRequired() {
            secureInstall = .needsAttention(.bundleWritable)
            operationMessage = MacStrings.secureInstallNeededSecureThe
        }

        /// A failed write stays pending in the UI coordinator for a later explicit flush.
        @discardableResult
        public func savePreferences() async -> Bool {
            let snapshot = preferences
            do { try await operations.savePreferences(snapshot); return true }
            catch { reportError(error); return false }
        }

        public func openCaptiveWindow() async {
            guard showsCaptiveButton else { return }
            await perform { try await self.operations.openCaptiveWindow(self.preferences.global.captiveWindowSeconds) }
        }

        public func closeCaptiveWindow() async {
            await perform { try await self.operations.closeCaptiveWindow() }
        }

        public func revisit(_ step: MacOnboardingStep) {
            onboardingStep = step
        }

        public func reportImportFailure(saving: Bool = false) {
            operationMessage = MacErrorCopy(saving ? .store : .importSource).message
        }

        public func reportDowngrade() {
            downgradeDetected = true; operationMessage = UserStrings.downgradeDetected
        }

        /// UI termination never owns tunnel lifetime (ADR-026).
        public func quit(terminate: () -> Void) {
            terminate()
        }

        package func perform(_ action: () async throws -> Void) async {
            guard !busy else { return }
            busy = true
            operationMessage = nil
            defer { busy = false }
            do { try await action() }
            catch { reportError(error) }
        }
    }

    public extension MacShellModel {
        /// Standard menu rows toggle the named tunnel, independently of the window's selection.
        func toggleMenuTunnel(_ id: UUID) async {
            guard !hostGuarded, !busy, pendingAction == nil,
                  ![ProtectionVerdict.unknown, .stale].contains(presentation.verdict),
                  let profile = profiles.first(where: { $0.id == id }) else { return }
            if activeProfileID == id {
                if isOnDemandArmed(id) {
                    await setOnDemand(false, for: profile)
                } else {
                    await disconnectActiveProfile()
                }
            } else {
                selectByAction(profile.id)
                await startSelectedProfile(fromMenu: true)
            }
        }

        func toggleActiveConnection() async {
            let selection = selectedProfileID
            if let activeProfileID {
                selectedProfileID = activeProfileID
            }
            await toggleConnection()
            selectedProfileID = selection
        }

        func sampleStatistics() async {
            guard !hostGuarded, simulated || daemonRunning else { return }
            do { try await receiveStatistics(backend.statistics()) }
            catch { statistics = nil }
        }

        /// Stores measured counters only. The chart never synthesises traffic.
        func receiveStatistics(_ sample: TunnelStatistics) {
            guard sample.generation == status.phase.generation?.rawValue, traffic.accepts(sample) else { return }
            traffic.append(sample)
            statistics = sample
        }

        var backendDescription: String {
            if simulated {
                return MacStrings.simulationNoVPNOrSystem
            }
            if hostGuarded {
                return MacShellCopy.hostGuard
            }
            switch daemonConnection {
            case let .connected(build): return MacStrings.daemonConnectedWithBuild(String(build))
            case .connecting: return MacStrings.connectingToTheDaemon
            case let .disconnected(error):
                return error.map { MacStrings.daemonDisconnected(String($0)) } ?? MacStrings.daemonDisconnectedStatus
            }
        }

        func receiveConnection(_ update: MacDaemonConnectionState) {
            guard !hostGuarded else { return }
            connectionRevision += 1
            daemonConnection = update
            secureInstallTask?.cancel()
            if case .connected = update {
                daemonRunning = true
                downgradeDetected = false
                secureInstallTask = Task { await self.refreshSecureInstall() }
            } else {
                daemonRunning = false
                secureInstall = .notReporting
                lastStatusAt = nil
            }
            if case .disconnected(lastError: "downgradeDetected") = update {
                reportDowngrade()
            }
        }

        func reportDaemonFailure() {
            guard serviceState == .enabled else { return }
            operationMessage = MacErrorCopy(.service).message
        }

        /// Deliberately derived from enforcement, even during preparing/reasserting.
        var showsCaptiveButton: Bool {
            status.protection == .blocked
        }

        var canSelectProfile: Bool {
            !busy
        }

        var canConnect: Bool {
            guard !hostGuarded else { return false }
            if windowPrimaryControl.armsOrDisarms {
                return canChangeOnDemand
            }
            switch detailPresentation.action {
            case .disconnect, .cancel, .checkAgain: return true
            default: return selectedProfile != nil && !busy && activationBlocker == nil
            }
        }

        /// Setup step 2 holds Continue until macOS reports the background service running (SPEC 7); step 3 has no Continue.
        var canAdvance: Bool {
            switch onboardingStep {
            case .welcome: true
            case .backgroundService: serviceState == .enabled && daemonRunning
            case .addTunnel: false
            }
        }
    }

    public extension MacShellModel {
        /// Connects the explicitly configured login profile after service registration has been confirmed.
        func connectAtLogin() async {
            guard !hostGuarded, !busy, serviceState == .enabled, daemonRunning, activeProfileID == nil,
                  let profile = profiles.first(where: { $0.macOptions.autoConnectAtLogin && canActivate($0) }) else { return }
            selectByAction(profile.id)
            await startSelectedProfile()
        }

        /// Presentation-only session origin, observed by the single UI coordinator.
        func recordSessionStart(at date: Date?) {
            traffic.startSession(at: date)
        }

        /// The shared presenter owns v2 colours and copy.
        var designPresentation: ProtectionPresentation {
            presentation
        }
    }
#endif
