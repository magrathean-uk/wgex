// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import NetworkExtension
import Observation
import SwiftUI
import WGEXAppComposition
import WGEXCore
import WGEXNEClient
import WGEXProfileStore
import WGEXUI
#if DEBUG || WGEX_LAB_BUILD
    import WGEXTesting
#endif
/// A backend whose tunnel keeps a statistics subscription only while a caller shows the numbers (M06-T02).
internal nonisolated protocol LiveStatisticsSource: Sendable {
    func startStatistics(interval: TimeInterval) async throws(TunnelError)
    func stopStatistics() async
}

extension NEManagerClient: LiveStatisticsSource {}

/// UI state is main-actor owned; ProfileStore serialises public document writes.
@MainActor @Observable
internal final class AppModel: IOSAppState {
    internal private(set) var profiles: [TunnelProfile] = []
    internal var selectedProfileID: UUID? {
        willSet {
            if let index = profiles.firstIndex(where: { $0.id == selectedProfileID }) {
                profiles[index].protection = protection
            }
        }
        didSet {
            settings.app.selectedProfileID = selectedProfileID
            if let profile = selectedProfile {
                protection = profile.protection
                if case .automatic = profile.transport.selection {
                    automaticFailover = true
                } else {
                    automaticFailover = false
                }
            }
        }
    }

    internal private(set) var status = TunnelStatus.idle {
        didSet { noteStatisticsOwner() }
    }

    /// The profile this app last asked to start; stands in for a backend that names no profile in its status.
    internal private(set) var requestedProfileID: UUID? {
        didSet { noteStatisticsOwner() }
    }

    internal private(set) var applyingProfileID: UUID?
    internal private(set) var statistics: TunnelStatistics?
    /// The tunnel `statistics` was read from; a sample never outlives a change of the active tunnel.
    internal private(set) var statisticsProfileID: UUID?
    /// Sampling period of `watchStatistics`; tests shorten it.
    @ObservationIgnored internal var statisticsInterval: Duration = .seconds(1)
    /// Reads one sample for `watchStatistics`; tests substitute a delayed reader.
    @ObservationIgnored internal var readStatistics: @Sendable () async throws -> TunnelStatistics
    /// The backend's statistics subscription, when it has one; tests substitute a recording source.
    @ObservationIgnored internal var liveStatistics: any LiveStatisticsSource?
    /// Bumped whenever the active tunnel changes, so a read started for the previous tunnel is dropped.
    @ObservationIgnored private var statisticsEpoch = 0
    /// The running tunnel the current epoch belongs to.
    @ObservationIgnored private var statisticsOwnerSeen = StatisticsOwner(profileID: nil, generation: nil)
    @ObservationIgnored private var apply = ApplyProgress()
    /// An edit's safety deadline reports an unconfirmed outcome. Tests shorten it.
    @ObservationIgnored internal var applyDeadline: Duration = .seconds(45)
    /// Hands a saved profile to the backend; tests substitute a delayed installer.
    @ObservationIgnored internal var installProfile: @Sendable (TunnelProfile) async throws -> Void
    internal var activeProfileID: UUID? {
        if let id = status.activeProfileID {
            return id
        }
        switch status.phase {
        case .idle, .failed: return nil
        default: return requestedProfileID
        }
    }

    internal var featureFlags: FeatureFlags = .defaults
    internal var protection = ProtectionPolicy(ipv6Policy: .tunnel)
    /// The policy a new tunnel starts with; on-demand is edited per tunnel (M06-T06), never app-wide.
    internal let onDemand: OnDemandPolicy = .off

    internal var automaticFailover = true
    /// Legacy `ios-shell.json` policy and profile, retained until saved and installed so failed migrations retry on launch.
    @ObservationIgnored internal var pendingLegacyOnDemand: OnDemandPolicy?
    @ObservationIgnored internal var pendingLegacyProfileID: UUID?
    /// Saved policies whose manager activation still needs to finish, retried on save or launch.
    @ObservationIgnored internal var pendingOnDemandActivation: Set<UUID> = []
    internal var notifications = true
    internal var onboardingComplete = false
    internal var operationMessage: String?
    internal private(set) var isBusy = false
    /// Pending reviews in order: one for a single source, one per configuration for an archive.
    internal var reviewQueue: [ImportReviewModel] = []
    internal var review: ImportReviewModel? {
        reviewQueue.first
    }

    internal var pendingReviewCount: Int {
        reviewQueue.count
    }

    internal var editor: ProfileEditorModel?
    internal var importDiagnostics: [ConfigDiagnostic] = []
    internal private(set) var statusHistory: [String] = []
    internal private(set) var settings = SettingsDocument()
    internal let backend: any TunnelBackend?
    internal let store: ProfileStore
    internal let secrets: any SecretStore
    @ObservationIgnored internal let secretComposition: ProfileComposition
    internal let container: URL
    internal let log: IOSLogState
    internal let usesFakeBackend: Bool
    internal let vpnUnavailableOnSimulator: Bool
    internal let appearanceOverride: ColorScheme?
    #if DEBUG || WGEX_LAB_BUILD
        private let scenario: FakeScenario?
    #endif
    @ObservationIgnored private var started = false
    private var manualStopRequested = false
    internal var userInitiated: Bool {
        manualStopRequested && status.protection == .unprotected
    }

    internal var preferenceSnapshot: ShellPreferences {
        ShellPreferences(
            onboardingComplete: onboardingComplete,
            profileOrder: profiles.map(\.id),
            protection: protection,
            legacyOnDemand: pendingLegacyOnDemand,
            legacyOnDemandProfileID: pendingLegacyProfileID,
            onDemandActivation: pendingOnDemandActivation.isEmpty ? nil : pendingOnDemandActivation
                .sorted { $0.uuidString < $1.uuidString },
            automaticFailover: automaticFailover,
        )
    }

    internal init(composition: IOSAppComposition) {
        usesFakeBackend = composition.usesFakeBackend
        vpnUnavailableOnSimulator = composition.vpnUnavailableOnSimulator
        secretComposition = composition.secretComposition
        appearanceOverride = composition.appearanceOverride
        backend = composition.backend
        if let backend = composition.backend {
            readStatistics = { try await backend.statistics() }
            installProfile = { try await backend.install($0) }
        } else {
            readStatistics = { throw TunnelError.backendUnavailable }
            installProfile = { _ in }
        }
        liveStatistics = composition.backend as? any LiveStatisticsSource
        secrets = composition.secrets
        container = composition.container
        log = IOSLogState(file: composition.logFile)
        store = ProfileStore(container: composition.container)
        #if DEBUG || WGEX_LAB_BUILD
            scenario = composition.scenario
        #endif
        if vpnUnavailableOnSimulator {
            operationMessage = Self.simulatorUnavailableMessage
        }
        if !usesFakeBackend {
            status.protection = .unknown
        }
    }

    /// Called by the root's structured task; cancellation ends the status subscription.
    internal func run() async {
        guard !started else { return }
        started = true
        logLifecycle(.started)
        defer { started = false; logLifecycle(.stopped) }
        do {
            settings = try await store.loadSettings()
            profiles = try await store.list()
            let preferencesURL = container.appendingPathComponent("ios-shell.json")
            var legacyOnDemand: OnDemandPolicy?
            var legacyProfileID: UUID?
            if FileManager.default.fileExists(atPath: preferencesURL.path) {
                let preferences = try JSONDecoder().decode(ShellPreferences.self, from: Data(contentsOf: preferencesURL))
                onboardingComplete = preferences.onboardingComplete
                protection = preferences.protection
                legacyOnDemand = preferences.legacyOnDemand
                legacyProfileID = preferences.legacyOnDemandProfileID
                pendingOnDemandActivation = Set(preferences.onDemandActivation ?? [])
                automaticFailover = preferences.automaticFailover
                let order = preferences.profileOrder
                profiles.sort { (order.firstIndex(of: $0.id) ?? Int.max) < (order.firstIndex(of: $1.id) ?? Int.max) }
            }
            // Parked transports stay hidden even when an older shell saved their experimental flag.
            featureFlags = .defaults
            notifications = settings.macGlobal.notifications
            selectedProfileID = settings.app.selectedProfileID ?? profiles.first?.id
            if let legacyOnDemand {
                await migrateOnDemand(legacyOnDemand, to: legacyProfileID ?? selectedProfileID)
            }
            await retryOnDemandActivations()
            #if DEBUG || WGEX_LAB_BUILD
                if let scenario {
                    prepareFixture()
                    await confirmImport()
                    onboardingComplete = true
                    // The fake names no profile in its status; the scenario's tunnel is the imported one.
                    requestedProfileID = selectedProfileID
                    (backend as? FakeTunnelBackend)?.publish(scenario.status)
                }
            #endif
        } catch { operationMessage = "Stored profiles could not be loaded." }
        guard let backend else { return }
        for await update in backend.statusUpdates() {
            if Task.isCancelled {
                break
            }
            receive(update)
            statusHistory.append(EventDescription.protectionText(update.protection))
            statusHistory = Array(statusHistory.suffix(32))
        }
    }
}

internal extension AppModel {
    /// The list follows the system: a tunnel started or stopped in Settings > VPN or by on-demand names its profile here.
    func receive(_ update: TunnelStatus) {
        if update.phase != status.phase {
            logPhase(update.phase)
        }
        // An idle or failed phase already names no tunnel; the last request is kept, as a late idle from the tunnel
        // stopped for a switch can arrive after the next start was asked for.
        status = update
        trackApply(update)
        if let id = update.activeProfileID, id != selectedProfileID, profiles.contains(where: { $0.id == id }) {
            selectedProfileID = id
        }
    }

    static func isSettled(_ phase: TunnelPhase) -> Bool {
        switch phase {
        case .idle, .active, .failed: true
        default: false
        }
    }

    static func isActive(_ phase: TunnelPhase) -> Bool {
        if case .active = phase {
            return true
        }
        return false
    }

    /// A sample belongs to one running tunnel: its profile and the generation the backend gave that run.
    private var statisticsOwner: StatisticsOwner {
        StatisticsOwner(profileID: activeProfileID, generation: status.phase.generation)
    }

    /// An active tunnel change drops the shown sample and in-flight reads, including a switch away and back.
    private func noteStatisticsOwner() {
        let owner = statisticsOwner
        guard owner != statisticsOwnerSeen else { return }
        statisticsOwnerSeen = owner
        statisticsEpoch &+= 1
        statistics = nil
        statisticsProfileID = nil
    }

    /// A tunnel switch interrupts an edit; restarting the edited tunnel waits for its own install result.
    private func trackApply(_ update: TunnelStatus) {
        guard let applying = applyingProfileID else { return }
        if let other = update.activeProfileID, other != applying {
            endApply(message: Self.applyInterruptedMessage)
        }
    }

    /// Starts an active tunnel edit's progress; only its install confirms success, while the deadline reports unconfirmed.
    private func beginApply(_ id: UUID) -> Int {
        apply.deadline?.cancel()
        let token = apply.token &+ 1
        apply = ApplyProgress(token: token)
        applyingProfileID = id
        let deadline = applyDeadline
        apply.deadline = Task { [weak self] in
            guard await (try? Task.sleep(for: deadline)) != nil, let self, apply.token == token else { return }
            endApply(message: Self.applyUnconfirmedMessage)
        }
        return token
    }

    /// Ends the current apply with an outcome: nil for success, otherwise the message shown.
    private func endApply(message: String?) {
        apply.deadline?.cancel()
        apply = ApplyProgress(token: apply.token &+ 1)
        applyingProfileID = nil
        operationMessage = message
    }

    /// The install of edit `token` returned: it ends the progress only while that edit is still the current one, so a
    /// late completion never clears a newer edit, a switch or a deadline already reported.
    private func finishApply(_ token: Int, _ outcome: Result<Void, any Error>) {
        guard apply.token == token, applyingProfileID != nil else { return }
        switch outcome {
        case .success: endApply(message: nil)
        case let .failure(error): endApply(message: Self.applyMessage(for: error))
        }
    }

    func commitImport(_ prepared: ProfileEditorModel, connect: Bool) async {
        guard !isBusy else { return }
        isBusy = true
        do {
            let profile = try prepared.validatedProfile()
            let saved = try await persist(profile, model: prepared)
            profiles.append(saved)
            selectedProfileID = saved.id
            advanceReview()
            operationMessage = nil
            await savePreferences()
            isBusy = false
            if connect {
                await toggleConnection()
            }
        } catch {
            isBusy = false
            operationMessage = "The profile could not be saved. Try again."
        }
    }

    /// Secret references and document commit are shared; the backend remains platform wiring. An edit of the on-demand
    /// options alone keeps the stored Keychain items and references, so the provider revision does not change and the
    /// running tunnel is neither reloaded nor restarted.
    func persist(_ profile: TunnelProfile, model: ProfileEditorModel) async throws -> TunnelProfile {
        let previous = try await storedProfile(profile.id)
        let packed = try model.makeSecrets()
        if let previous, Self.differsOnlyInOnDemand(profile, from: previous) {
            let storedKeys = try await secretComposition.load(previous)
            if try Self.keysMatch(packed, stored: storedKeys) {
                return try await saveKeepingKeys(profile, previous: previous)
            }
        }
        return try await secretComposition.commit(
            profile, secrets: packed, to: store, previous: previous,
            install: { try await self.installProfile($0) },
            rollback: {
                if let previous {
                    try? await self.installProfile(previous)
                }
            },
        )
    }

    func toggleConnection() async {
        guard !isBusy else { return }
        guard backend != nil else {
            operationMessage = backendMessage
            return
        }
        guard let id = selectedProfileID else { return }
        switch status.phase {
        case .active, .preparing, .configuring, .reasserting, .stopping, .captiveWindow:
            await setTunnel(activeProfileID ?? id, on: false)
        case .idle, .failed:
            await setTunnel(id, on: true)
        }
    }

    /// One VPN at a time on iOS: turning a tunnel on stops whichever other one is up before starting it.
    func setTunnel(_ id: UUID, on: Bool) async {
        guard !isBusy else { return }
        guard let backend else {
            operationMessage = backendMessage
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            if on {
                if let running = activeProfileID, running != id {
                    manualStopRequested = true
                    try await backend.stop(running)
                }
                if selectedProfileID != id {
                    selectedProfileID = id
                }
                manualStopRequested = false
                requestedProfileID = id
                try await backend.start(id, transport: nil)
            } else {
                manualStopRequested = true
                try await backend.stop(id)
            }
            operationMessage = nil
        } catch { operationMessage = "The connection request failed. Protection cannot be assumed." }
    }

    /// The provider's subscription accepts 2 to 3600 seconds; the detail still reads a fresh sample every second.
    static let statisticsSubscriptionInterval: TimeInterval = 2

    /// Polls only while a caller's task runs: a detail view on screen. Cancellation ends the loop and the subscription.
    /// The subscription is asked for once per tunnel; a rejection is not repeated, and reads go on without it.
    func watchStatistics() async {
        let live = liveStatistics
        var asked: UUID?
        var subscribed = false
        while !Task.isCancelled {
            if backend != nil, let active = activeProfileID, isTunnelOn(active) {
                if asked != active, let live {
                    asked = active
                    do {
                        try await live.startStatistics(interval: Self.statisticsSubscriptionInterval)
                        subscribed = true
                    } catch { /* Rejected or unknown: the source keeps what it had; reads continue. */ }
                }
                let epoch = statisticsEpoch
                let sample = try? await readStatistics()
                // A read that outlived its tunnel (a switch, an external start, a restart) is dropped.
                if epoch == statisticsEpoch, activeProfileID == active, !Task.isCancelled {
                    statistics = sample
                    statisticsProfileID = sample == nil ? nil : active
                }
            } else {
                clearStatistics()
                asked = nil
                if subscribed {
                    subscribed = false
                    await live?.stopStatistics()
                }
            }
            do { try await Task.sleep(for: statisticsInterval) }
            catch { break }
        }
        clearStatistics()
        if subscribed {
            await live?.stopStatistics()
        }
    }

    private func clearStatistics() {
        statistics = nil
        statisticsProfileID = nil
    }

    func deleteProfile(_ id: UUID) async {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return }
        await deleteProfiles(at: IndexSet(integer: index))
    }

    func deleteProfiles(at offsets: IndexSet) async {
        guard !isBusy else { return }
        let deleting = offsets.compactMap { profiles.indices.contains($0) ? profiles[$0] : nil }
        isBusy = true
        defer { isBusy = false }
        do {
            for profile in deleting {
                // One VPN at a time on iOS: a tunnel known to run elsewhere means this one is down. Otherwise the app
                // cannot rule out that this profile runs (unknown, idle or failed status), so it is stopped first.
                if activeProfileID == nil || activeProfileID == profile.id {
                    if activeProfileID == profile.id {
                        manualStopRequested = true
                    }
                    // Tolerated like remove: with the iOS VPN configuration gone there is nothing to stop, and the
                    // profile must still be deletable. Any other failure still blocks, as the tunnel may be running.
                    do { try await backend?.stop(profile.id) }
                    catch TunnelError.profileNotFound { /* No manager: nothing is running. */ }
                }
                do { try await backend?.remove(profile.id, purgeSecrets: true) }
                catch TunnelError.profileNotFound { /* Never installed in the backend: nothing to remove there. */ }
                // Secrets before the document: a failure here keeps the document, so a retry still knows every
                // reference; absent items are not an error. No single failure can strand items without a document.
                try await secretComposition.deleteSecrets(of: profile)
                try await store.delete(profile.id)
                profiles.removeAll { $0.id == profile.id }
                pendingOnDemandActivation.remove(profile.id)
                if requestedProfileID == profile.id {
                    requestedProfileID = nil
                }
                if applyingProfileID == profile.id {
                    endApply(message: Self.applyInterruptedMessage)
                }
            }
            if !profiles.contains(where: { $0.id == selectedProfileID }) {
                selectedProfileID = profiles.first?.id
            }
            await savePreferences()
        } catch { operationMessage = "The profile could not be deleted. Try again." }
    }

    func moveProfiles(from offsets: IndexSet, to destination: Int) {
        guard destination >= 0, destination <= profiles.count, offsets.allSatisfy({ profiles.indices.contains($0) }) else { return }
        profiles.move(fromOffsets: offsets, toOffset: destination)
    }

    func openEditor(_ profile: TunnelProfile) async {
        do {
            let packed = try await secretComposition.load(profile)
            editor = try ProfileEditorModel(profile: profile, secrets: packed, featureFlags: featureFlags)
        } catch SecretStoreError.notFound where usesFakeBackend {
            operationMessage = "Profile keys are unavailable. Import the profile again."
        } catch { operationMessage = "Profile keys are unavailable." }
    }

    func saveEditor(_ profile: TunnelProfile, secrets: borrowing ParsedSecrets) throws {
        let saved = try ProfileEditorModel(profile: profile, secrets: secrets, featureFlags: featureFlags)
        Task { await commitEdit(profile, model: saved) }
    }

    /// Saves an edit and waits for the backend to apply it. Progress on a running tunnel ends only on installation,
    /// a reported failure or interruption, or the safety deadline. Failed on-demand activation remains pending for retry.
    func commitEdit(_ profile: TunnelProfile, model saved: ProfileEditorModel) async {
        isBusy = true
        operationMessage = nil
        defer { isBusy = false }
        let token = isTunnelOn(profile.id) ? beginApply(profile.id) : nil
        do {
            let previous = try await storedProfile(profile.id)
            let stored = try await persist(profile, model: saved)
            // A new policy arms or disarms the manager. Existing policies only retry pending activation, so an ordinary
            // save never re-arms a tunnel the user turned off.
            let policyEdited = previous.map { $0.onDemand != stored.onDemand } ?? IOSOnDemandForm(policy: stored.onDemand).isEnabled
            if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
                profiles[index] = stored
            } else {
                // Create from scratch: the first save adds the new profile.
                profiles.append(stored)
                selectedProfileID = stored.id
                await savePreferences()
            }
            if selectedProfileID == profile.id {
                protection = stored.protection
            }
            editor = nil
            let needsActivation = policyEdited || pendingOnDemandActivation.contains(stored.id)
            let followed = needsActivation ? await settleOnDemandEdit(stored.id) : true
            if let token {
                finishApply(token, .success(()))
            }
            if !followed {
                operationMessage = Self.onDemandFailedMessage
            }
        } catch {
            if let token {
                finishApply(token, .failure(error))
            } else {
                operationMessage = Self.editSaveFailedMessage
            }
        }
    }

    func closeEditor() {
        editor = nil
    }

    func savePreferences() async {
        settings.app.featureFlags = featureFlags
        settings.app.selectedProfileID = selectedProfileID
        settings.macGlobal.notifications = notifications
        do {
            if let index = profiles.firstIndex(where: { $0.id == selectedProfileID }) {
                profiles[index].protection = protection
                setFailover(&profiles[index])
                try await store.save(profiles[index])
            }
            try await store.saveSettings(settings)
            try writeShellPreferences()
        } catch { operationMessage = "Settings could not be saved." }
    }

    /// Replaces the listed copy of a stored profile (the on-demand migration in ShellPreferences.swift).
    func replaceProfile(_ profile: TunnelProfile) {
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        }
    }

    func setFailover(_ profile: inout TunnelProfile) {
        let order = profile.transport.candidates.map(\.id)
        if automaticFailover {
            profile.transport.selection = .automatic(.defaults(order: order))
        } else if let first = order.first {
            profile.transport.selection = .manual(first)
        }
    }
}

/// The running tunnel a statistics sample belongs to.
private struct StatisticsOwner: Equatable {
    let profileID: UUID?
    let generation: Generation?
}

/// The saved edit of the running tunnel whose apply is shown; a newer edit, outcome or interruption advances the token.
private struct ApplyProgress {
    var token = 0
    var deadline: Task<Void, Never>?
}
