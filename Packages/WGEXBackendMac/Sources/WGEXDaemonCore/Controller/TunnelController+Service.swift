// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXProfileStore

extension TunnelController: DaemonService {
    public func ownerUID(for profileID: UUID) async -> uid_t? {
        try? await registry.ownerUID(for: profileID)
    }

    public func profileIDs(ownedBy uid: uid_t) async -> Set<UUID> {
        await (try? registry.profileIDs(ownedBy: uid)) ?? []
    }

    public func protectionOwnerUID() -> uid_t? {
        intended?.ownerUID ?? journal.snapshot().protectionOwnerUID
    }

    package func recordDiagnostics(_ item: DaemonServiceEvent) async -> RedactedLogLine? {
        await diagnostics.record(item)
    }

    /// Retains the failed teardown target so dispatcher stop-current retries remain owner-authenticated.
    public func activeProfileID() -> UUID? {
        intended?.profileID ?? pendingTeardownProfileID
    }

    public func currentSettings() -> MacGlobalSettings {
        settings
    }

    /// The controller asks the app for missing secrets inside the command that found them missing (`withAppSecrets`).
    public nonisolated var ownsAppSecretHandoff: Bool {
        true
    }

    /// Authentication/console/admin checks belong to DaemonDispatcher. Registry methods recheck ownership.
    public func handle(_ request: Request, context: DaemonRequestContext, secrets: consuming SecretBundle?) async -> Reply {
        do {
            try requireUninstallAdmission(request.kind)
            if case let .uninstall(purgeState) = request {
                // Admitted while recovering and after a failed step, so a retry resumes (M05-T07).
                try await uninstall(purgeState: purgeState)
                return .ok
            }
            if ![.status, .statistics, .logs, .diagnostics, .secureInstallStatus, .performSecureInstall].contains(request.kind) {
                guard acceptingRequests else { throw DaemonFailure.controllerRecoveryRequired }
                try checkExpected(context.expectedGeneration)
            }
            try validateCutoverControl(request)
            if [
                .selectTransport,
                .openCaptiveWindow,
                .extendCaptiveWindow,
            ].contains(request.kind) {
                try await requireSecureInstall()
            }
            switch request {
            case .startCutover, .confirmCutover, .abortCutover, .armOnDemand, .disarmOnDemand, .reportWiFiNetwork:
                return try await handleCutoverOrOnDemand(request, context: context, bundle: secrets)
            case let .startIntent(id, transport, _):
                return try await manualStart(id, transport: transport, context: context, payload: Self.pendingSecrets(consume secrets))
            case let .setStartBeforeLoginIntent(id, enabled):
                return try await changeBootIntent(id, enabled: enabled, context: context, payload: Self.pendingSecrets(consume secrets))
            default:
                return try await handlePublic(request, context: context)
            }
        } catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(error, context: "request")
            #endif
            return await .error(wireError(error, profileID: request.profileID))
        }
    }

    /// A manual connect: its override and its reservation run under one admission (ADR-030 rules 4 and 5); the secure-install
    /// check holds nothing, and a stop received before the reservation supersedes this start. Missing daemon-store secrets are
    /// requested from the app inside the same admission (`withAppSecrets`).
    private func manualStart(
        _ id: UUID, transport: TransportID?, context: DaemonRequestContext, payload: PendingDaemonSecrets?,
    ) async throws -> Reply {
        try await withCommand(.manualStart, profile: id) { admission in
            try await prepareStart(admission, profileID: id)
            try await manualConnectOverridesOnDemand(id, admission: admission)
            return try await withAppSecrets(id, payload: payload, handoff: context.appSecrets, admission: admission) { admission, payload in
                try await .started(start(
                    profileID: id, connectionUID: context.peer.uid, payload: payload, transport: transport,
                    expectedGeneration: context.expectedGeneration, origin: .manual, admission: admission,
                ))
            }
        }
    }

    private func changeBootIntent(
        _ id: UUID, enabled: Bool, context: DaemonRequestContext, payload: PendingDaemonSecrets?,
    ) async throws -> Reply {
        defer { payload?.wipe() }
        return try await withCommand(enabled ? .bootEnable : .bootDisable, profile: id) { admission in
            if enabled {
                try await requireSecureInstall()
            }
            if !enabled, needsRecovery {
                let lineage = admission.lineage
                try await repairRegistration { controller in
                    try await controller.registry.setStartBeforeLogin(
                        id, enabled: false, connectionUID: context.peer.uid, admission: controller.readmit(lineage),
                    )
                }
                return .ok
            }
            try await setBootIntent(id, enabled: enabled, uid: context.peer.uid, payload: payload, admission: admission)
            await onDemandProfileChanged(id, admission: admission)
            return .ok
        }
    }

    private func validateCutoverControl(_ request: Request) throws {
        if journal.snapshot().cutover?.rollbackPending == true {
            if case let .stop(id, _) = request, id != journal.snapshot().cutover?.profileID {
                throw DaemonFailure(code: .slotRefused)
            }
            guard [.status, .statistics, .logs, .diagnostics, .secureInstallStatus, .abortCutover, .stop, .stopCurrent]
                .contains(request.kind) else { throw DaemonFailure(code: .slotRefused) }
            return
        }
        guard cutoverIsArmed else { return }
        switch request {
        case .startIntent, .startCutover, .prepareForUpdate, .openCaptiveWindow, .extendCaptiveWindow, .armOnDemand:
            throw DaemonFailure(code: .slotRefused)
        case .setStartBeforeLoginIntent(_, true): throw DaemonFailure(code: .slotRefused)
        case let .removeProfile(id, _) where id == journal.snapshot().cutover?.profileID: throw DaemonFailure(code: .slotRefused)
        case let .setGlobalSettings(requested) where requested.lockdown: throw DaemonFailure(code: .slotRefused)
        default: break
        }
    }

    private func handleCutoverOrOnDemand(
        _ request: Request, context: DaemonRequestContext, bundle: consuming SecretBundle?,
    ) async throws -> Reply {
        if [.armOnDemand, .disarmOnDemand, .reportWiFiNetwork].contains(request.kind) {
            return try await handleOnDemand(request, context: context, bundle: bundle)
        }
        return try await handleCutover(request, context: context, bundle: bundle)
    }

    /// ADR-030 requests; replies are `.ok` or `.error`.
    private func handleOnDemand(_ request: Request, context: DaemonRequestContext, bundle: consuming SecretBundle?) async throws -> Reply {
        switch request {
        case let .armOnDemand(id, _): try await armOnDemand(id, uid: context.peer.uid, bundle: bundle, appSecrets: context.appSecrets)
        case let .disarmOnDemand(id): try await disarmOnDemand(id, uid: context.peer.uid)
        case let .reportWiFiNetwork(observation): acceptWiFiReport(observation, reporter: context.wifiReporter, uid: context.peer.uid)
        default: throw DaemonError.malformedMessage
        }
        return .ok
    }

    private func handleCutover(_ request: Request, context: DaemonRequestContext, bundle: consuming SecretBundle?) async throws -> Reply {
        switch request {
        case let .startCutover(id, seconds, _):
            return try await .started(startCutover(
                profileID: id, connectionUID: context.peer.uid, confirmWithin: seconds,
                secrets: bundle, expectedGeneration: context.expectedGeneration, appSecrets: context.appSecrets,
            ))
        case .confirmCutover: try await confirmCutover(connectionUID: context.peer.uid)
        case .abortCutover: try await abortCutover(connectionUID: context.peer.uid)
        default: throw DaemonError.malformedMessage
        }
        return .ok
    }

    private func handlePublic(_ request: Request, context: DaemonRequestContext) async throws -> Reply {
        switch request {
        case .installProfile: return .error(.malformedMessage) // Installs use the CAS port exclusively.
        case let .removeProfile(id, purge):
            try await removeRegisteredProfile(id, purge: purge, context: context)
        case let .stop(id, reason):
            if cutoverNeedsRollback, journal.snapshot().cutover?.profileID == id {
                try await abortCutover(connectionUID: context.peer.uid)
                return .ok
            }
            // A manual disconnect and its on-demand override run under one admission (ADR-030 rule 3).
            try await withCommand(reason == .userRequested ? .manualStop : .stop, profile: id) { admission in
                if reason == .userRequested {
                    try await manualDisconnectOverridesOnDemand(id, admission: admission)
                }
                try await stop(
                    profileID: id, connectionUID: context.peer.uid, reason: reason,
                    expectedGeneration: context.expectedGeneration, retainingSecrets: false, admission: admission,
                )
            }
        case let .stopCurrent(reason):
            try await stopCurrentIfNeeded(reason: reason, uid: context.peer.uid)
        case let .selectTransport(id, selection):
            try await selectTransport(id, selection: selection, uid: context.peer.uid)
        default: return try await handleProtection(request, context: context)
        }
        return .ok
    }

    private func stopCurrentIfNeeded(reason: StopReason, uid: UInt32) async throws {
        if cutoverNeedsRollback {
            try await abortCutover(connectionUID: uid)
            return
        }
        // The current profile is resolved at admission, before any await.
        guard let target = intended?.profileID ?? pendingTeardownProfileID else { return }
        try await withCommand(reason == .userRequested ? .manualStop : .stop, profile: target) { admission in
            if reason == .userRequested {
                try await manualDisconnectOverridesOnDemand(target, admission: admission)
            }
            try await stop(profileID: target, connectionUID: uid, reason: reason, retainingSecrets: false, admission: admission)
        }
    }

    private func handleProtection(_ request: Request, context: DaemonRequestContext) async throws -> Reply {
        switch request {
        case let .setGlobalSettings(settings):
            try await setGlobalSettings(settings, connectionUID: context.peer.uid)
        case let .openCaptiveWindow(seconds), let .extendCaptiveWindow(seconds):
            try await openCaptiveWindow(seconds: seconds, connectionUID: context.peer.uid)
        case .closeCaptiveWindow: try await closeCaptiveWindow()
        case .prepareForUpdate: try await prepareForUpdate()
        case let .uninstall(purgeState): try await uninstall(purgeState: purgeState)
        case .subscribeEvents: return .ok // Dispatcher owns subscriptions.
        default: return try await handleRead(request, context: context)
        }
        return .ok
    }

    private func handleRead(_ request: Request, context: DaemonRequestContext) async throws -> Reply {
        switch request {
        case .secureInstallStatus: return await .secureInstall(secureInstall.status())
        case .performSecureInstall:
            let report = await secureInstall.perform()
            if report.state == .verified {
                // The fresh install that ends a completed uninstall (M05-T07); when it re-entered the runtime's startup
                // sequence, that sequence owns the retry (M05-T18).
                let resumed = try await clearUninstallAfterFreshInstall()
                try await requireSecureInstall()
                if resumed {
                    return .secureInstall(report)
                }
                if needsRecovery || startup.reconciliationPending {
                    requestStartupRetry()
                } else {
                    Task { try? await tick() }
                }
            }
            return .secureInstall(report)
        case .status: return .status(snapshot)
        case .statistics:
            return try await .statistics(sampleStatistics())
        case let .logs(since, limit):
            let lines = try await diagnostics.logs(
                since: since,
                limit: max(0, min(limit, 512)),
                visibleProfileIDs: context.visibleProfileIDs,
            )
            return .logs(lines.filter { $0.profileID.map(context.visibleProfileIDs.contains) ?? true })
        case let .diagnostics(options):
            let visible = context.visibleProfileIDs.intersection(options.profileIDs)
            return try await .diagnostics(diagnostics.bundle(options, visibleProfileIDs: visible))
        default: throw DaemonError.malformedMessage
        }
    }

    private func sampleStatistics() async throws -> TunnelStatistics {
        let epoch = generation
        guard let engine = engines[epoch] else { throw DaemonFailure.controllerNotActive }
        var sample = try await engine.statistics()
        try check(epoch)
        sample.generation = epoch.rawValue
        wireEvents.yield(DaemonServiceEvent(
            event: .statistics(sample),
            profileID: intended?.profileID,
            ownerUID: protectionOwnerUID(),
        ))
        return sample
    }

    /// A removal is a stop kind with a removal hold: older starts, arms and on-demand actions of the profile are superseded at
    /// its admission, and newer starts, arms, installs and start-before-login changes of it are refused until it ends (rule 8).
    /// The purge is two-phase: the tombstone and the removal commit synchronously, the secret deletion follows idempotently.
    private func removeRegisteredProfile(_ id: UUID, purge: Bool, context: DaemonRequestContext) async throws {
        try await withCommand(.remove, profile: id) { admission in
            guard let owner = try await registry.ownerUID(for: id) else { throw DaemonFailure.registryNotFound }
            guard owner == context.peer.uid else { throw DaemonFailure.registryNotOwner }
            try validateCutoverControl(.removeProfile(id, purgeSecrets: purge))
            try await onDemandProfileRemoving(id, admission: admission)
            if intended?.profileID == id {
                try await stop(
                    profileID: id,
                    connectionUID: context.peer.uid,
                    reason: .profileRemoved,
                    expectedGeneration: context.expectedGeneration,
                    retainingSecrets: false,
                    admission: admission,
                )
            }
            if needsRecovery {
                let lineage = admission.lineage
                try await repairRegistration { controller in
                    try await controller.registry.removeProfile(
                        id, purgeSecrets: purge, connectionUID: context.peer.uid, admission: controller.readmit(lineage),
                    )
                }
            } else {
                try await registry.removeProfile(id, purgeSecrets: purge, connectionUID: context.peer.uid, admission: admission)
            }
            await refreshArmedSelection()
            // The armed retention goes with the profile: its release finds no other retention reason left.
            _ = try? await completeReleases(of: [id], for: admission)
        }
    }

    /// The dispatcher lost an eligible Wi-Fi reporter (ADR-030 section 3): an input that invalidates in its own turn.
    public func wifiReporterLost() async {
        onDemandInput(.reporterLost)
    }

    /// A start-before-login change runs under its own admission with nothing held: no lifecycle operation, so a stop never
    /// waits for its registry or secret writes.
    private func setBootIntent(
        _ id: UUID, enabled: Bool, uid: UInt32, payload: PendingDaemonSecrets?, admission: borrowing Admission,
    ) async throws {
        guard !needsRecovery else { throw DaemonFailure.controllerRecoveryRequired }
        guard try await performSetBootIntent(id, enabled: enabled, uid: uid, payload: payload, admission: admission) else {
            throw DaemonFailure(code: .slotRefused)
        }
    }

    private func performSetBootIntent(
        _ id: UUID, enabled: Bool, uid: UInt32, payload: PendingDaemonSecrets?, admission: borrowing Admission,
    ) async throws -> Bool {
        guard !enabled || !cutoverIsArmed else { return false }
        let record = try await registry.registrationForStart(id, connectionUID: uid)
        guard enabled else {
            await pauseOnDemand(.bootCommit(id))
            try await registry.setStartBeforeLogin(id, enabled: false, connectionUID: uid, admission: admission)
            return true
        }
        return try await commitBootIntent(record, uid: uid, payload: payload, admission: admission)
    }

    /// Start-before-login is a retention claim: the bundle publication (one of the profile's ordered secret writes), the
    /// supersession of an older journalled deletion and the durable flag; a deletion decided between the publication and the
    /// flag treats the profile as retained (`publishing`) (ADR-030 section 7).
    private func commitBootIntent(
        _ record: RegisteredProfile, uid: UInt32, payload: PendingDaemonSecrets?, admission: borrowing Admission,
    ) async throws -> Bool {
        let id = record.registration.profile.id
        publishing[id, default: 0] += 1
        defer { endPublishing(id) }
        guard !cutoverIsArmed else { return false }
        if let payload {
            _ = try Self.pack(SecretsWireLayout.decode(payload.copy()), profile: record.registration.profile)
            guard try await publishBundle(payload, for: record.registration) else { throw DaemonFailure.registryRevisionConflict }
        } else {
            // No payload (the CLI holds no Keychain): the daemon's stored key is the key, and none is a refusal the caller can name.
            let stored: SecretBytes
            do { stored = try await secrets.loadBundle(profileID: id) }
            catch SecretStoreError.notFound { throw DaemonError.secretsUnavailable }
            _ = try Self.pack(SecretsWireLayout.decode(stored), profile: record.registration.profile)
        }
        guard !cutoverIsArmed else { return false }
        try admission.requireLive()
        try journal.mutate(generation: nil) { $0.pendingSecretDeletions.remove(id) }
        await pauseOnDemand(.bootCommit(id))
        try await registry.setStartBeforeLogin(id, enabled: true, connectionUID: uid, admission: admission)
        return true
    }

    private func selectTransport(_ id: UUID, selection: TransportID?, uid: UInt32) async throws {
        let record = try await registry.registrationForStart(id, connectionUID: uid)
        let selected = selection.flatMap { id in record.registration.profile.transport.candidates.first { $0.id == id } }
            ?? record.registration.profile.transport.candidates.first
        guard let selected, selection == nil || selected.id == selection else { throw DaemonFailure.controllerInvalidConfiguration }
        guard intended?.profileID == id else { throw DaemonFailure.controllerNotActive }
        try await maintenance { controller, epoch in
            guard let engine = controller.engines[epoch] else { throw DaemonFailure.controllerNotActive }
            try await engine.setTransport(selected.spec)
            try controller.check(epoch)
            controller.snapshot.transport = selected.id
            try await controller.applyPolicy(.connecting(
                resolvers: controller.underlay.resolvers,
                endpoints: controller.endpointAddresses,
            ), generation: epoch)
            controller.transition(.reasserting(epoch, reason: .transportSwitch), protection: .blocked)
        }
    }

    /// Quiesce while preserving durable intent and encrypted secrets. The executable exits only after the reply barrier.
    public func prepareForUpdate() async throws {
        acceptingRequests = false
        do {
            if let intended {
                try await withCommand(.stop, profile: intended.profileID, input: false) { admission in
                    try await stop(
                        profileID: intended.profileID, connectionUID: intended.ownerUID, reason: .update, retainingSecrets: false,
                        admission: admission, preemptible: true,
                    )
                }
            }
        } catch {
            acceptingRequests = true
            throw error
        }
    }

    private func wireError(_ error: any Error, profileID: UUID?) async -> DaemonError {
        if let error = error as? DaemonError {
            return error
        }
        if let failure = error as? DaemonFailure {
            return failure.wireError(profileID: profileID, protectionFailureReason: protectionFailureReason)
        }
        if (error as? EngineError) == .deviceClosed {
            return .tunnel(.engine(code: -9))
        }
        if let protectionFailureReason {
            return .protectionUnknown(reason: protectionFailureReason)
        }
        return .tunnel(.backendUnavailable)
    }
}
