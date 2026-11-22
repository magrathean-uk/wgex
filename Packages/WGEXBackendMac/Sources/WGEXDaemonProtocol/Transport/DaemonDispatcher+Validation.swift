// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

package extension DaemonDispatcher {
    func validateRecoveryRequest(_ request: Request) async throws {
        switch request {
        case .status, .statusTelemetry, .protectionReasons, .secureInstallStatus, .performSecureInstall, .subscribeEvents, .stop,
             .stopCurrent, .abortCutover,
             .removeProfile, .disarmOnDemand,
             .installProfile, .installProfileCAS, .profileRevision,
             .uninstall: return // Uninstall is also the way out of a recovery that cannot finish (M05-T07).
        case .setStartBeforeLoginIntent(_, false): return
        case let .setGlobalSettings(requested):
            let current = await service.currentSettings()
            guard AuthorisationTable.recoveryAllows(from: current, to: requested),
                  (1 ... 3600).contains(requested.captiveWindowSeconds) else { throw DaemonError.recovering }
        default: throw DaemonError.recovering
        }
    }

    /// Installs and closes the run's first-publication fence (DEC-011), before the listener starts.
    func armStartupFence(_ fence: StartupFence) {
        startupFence = fence
        fence.arm()
    }

    /// Publishes the run's first status to subscribers, then opens the fence: held requests proceed only after it (DEC-011),
    /// and held status reads measure their own current sample. The fence keeps the publication as qualified here, the same
    /// status a subscriber receives, for the rest of the run (DEC-018).
    func openStartupFence(first: StatusMeasurement?) async {
        guard let fence = startupFence else { return }
        var record = first
        if let first {
            let qualified = await service.qualifyStatus(first.status, profileID: first.status.activeProfileID)
            if let status = try? await measured(qualified.status) {
                record = first.replacing(status: status)
            }
        }
        if let record, hasSubscribers {
            await publish(.status(record.status), profileID: record.status.activeProfileID, ownerUID: record.ownerUID)
        }
        fence.open(first: record)
    }

    /// Before the first publication only the handshake, subscriptions and plain reads pass. A status read waits briefly, then
    /// answers `recovering`; any other request waits for the publication within its client budget, then answers `recovering`
    /// unserved, so a client is never left without a reply while startup restores the policy.
    func holdForFirstPublication(_ request: Request) async throws {
        guard let fence = startupFence, !fence.isOpen else { return }
        let bound: Duration
        switch request {
        case .hello, .subscribeEvents, .secureInstallStatus, .profileRevision: return
        case .status, .statusTelemetry, .protectionReasons: bound = StartupFence.statusHold
        default: bound = RequestDeadline.duration(for: request) - .seconds(1)
        }
        guard await fence.wait(bound: bound, clock: clock) else { throw DaemonError.recovering }
    }

    /// Used only after an authorised start reports missing daemon-store secrets.
    func requestSecrets(profileID: UUID, uid: uid_t) async throws -> SecretBundle {
        guard await service.ownerUID(for: profileID) == uid else { throw DaemonError.unauthorised }
        let deadline = clock.now() + 5
        var refusal: DaemonFailure?
        for candidate in connections.values where candidate.peer.uid == uid && candidate.clientBuild != nil && candidate.subscribed {
            guard await authorisation.isConsoleUser(candidate.peer) else { continue }
            do {
                try Task.checkCancellation()
                let remaining = deadline - clock.now()
                guard remaining > 0 else { throw DaemonError.tunnel(.timedOut) }
                let data = try await SecretsCallback.wait(
                    profileID: profileID, callback: candidate.callbacks.provideSecrets, clock: clock, remaining: .seconds(remaining),
                )
                defer { SecretsWireLayout.wipeReceived(data) }
                return try decodeAppSecrets(data)
            } catch {
                let failure = SecretsCallback.failure(error)
                secretFailure(failure)
                if failure.kind != .secretsUnavailable || refusal == nil {
                    refusal = failure
                }
                if failure.kind == .tunnelTimedOut || failure.kind == .tunnelCancelled {
                    throw failure
                }
            }
        }
        let failure = refusal ?? DaemonFailure(wire: .secretsUnavailable)
        if refusal == nil {
            secretFailure(failure)
        }
        throw failure
    }

    private func decodeAppSecrets(_ data: Data) throws -> SecretBundle {
        guard !data.isEmpty else { throw DaemonError.secretsUnavailable }
        guard data.count <= Self.maximumPayloadSize else { throw DaemonError.messageTooLarge(data.count) }
        do { return try SecretsWireLayout.decodeReceived(data) }
        catch { throw DaemonError.malformedMessage }
    }

    /// Hands the request to the service. A start, cutover or arm sent without secrets gets the requester's app's secrets
    /// inside the service's own command when the service owns the handoff, otherwise through the dispatcher's retry.
    func serve(_ request: Request, context: DaemonRequestContext, secrets bundle: consuming SecretBundle?) async throws -> Reply {
        let owned = service.ownsAppSecretHandoff
        var context = context
        if owned, Self.mayRequestAppSecrets(request) {
            context.appSecrets = appSecretsHandoff(uid: context.peer.uid)
        }
        let reply = await service.handle(request, context: context, secrets: bundle)
        if !owned, reply == .error(.secretsUnavailable), let supplied = try await startUsingAppSecrets(request, context: context) {
            return supplied
        }
        return reply
    }

    /// A start, cutover or arm sent without secrets: the service may ask the requester's app for them.
    static func mayRequestAppSecrets(_ request: Request) -> Bool {
        switch request {
        case .startCutover(_, _, false), .startIntent(_, _, false), .armOnDemand(_, false): true
        default: false
        }
    }

    /// The handoff a service that owns it calls inside its command (`requestSecrets`, for the requester's uid).
    func appSecretsHandoff(uid: uid_t) -> AppSecretsHandoff {
        AppSecretsHandoff { [weak self] profileID in
            guard let self else { throw DaemonError.disconnected }
            return try await requestSecrets(profileID: profileID, uid: uid)
        }
    }

    /// The dispatcher's retry for a service that does not own the handoff.
    func startUsingAppSecrets(_ request: Request, context: DaemonRequestContext) async throws -> Reply? {
        switch request {
        case let .startCutover(profileID, seconds, false):
            let supplied = try await requestSecrets(profileID: profileID, uid: context.peer.uid)
            return await service.handle(
                .startCutover(profileID: profileID, confirmWithin: seconds, hasSecrets: true), context: context, secrets: supplied,
            )
        case let .startIntent(profileID, transport, false):
            let supplied = try await requestSecrets(profileID: profileID, uid: context.peer.uid)
            return await service.handle(
                .startIntent(profileID: profileID, transport: transport, hasSecrets: true), context: context, secrets: supplied,
            )
        case let .armOnDemand(profileID, false):
            let supplied = try await requestSecrets(profileID: profileID, uid: context.peer.uid)
            return await service.handle(.armOnDemand(profileID: profileID, hasSecrets: true), context: context, secrets: supplied)
        default: return nil
        }
    }

    func validateSecretMethod(_ request: Request, secrets: Data) throws {
        switch request {
        case let .startIntent(_, _, hasSecrets), let .startCutover(_, _, hasSecrets), let .armOnDemand(_, hasSecrets):
            guard hasSecrets == !secrets.isEmpty else { throw DaemonError.malformedMessage }
        case let .setStartBeforeLoginIntent(_, enabled):
            guard enabled || secrets.isEmpty else { throw DaemonError.malformedMessage }
        default:
            guard secrets.isEmpty else { throw DaemonError.malformedMessage }
        }
        try validateBounds(request)
    }

    private func validateBounds(_ request: Request) throws {
        if case let .logs(_, limit) = request, !(0 ... 1024).contains(limit) {
            throw DaemonError.malformedMessage
        }
        switch request {
        case let .startCutover(_, seconds, _):
            guard (60 ... 3600).contains(seconds) else { throw DaemonError.malformedMessage }
        case let .openCaptiveWindow(seconds), let .extendCaptiveWindow(seconds):
            guard (1 ... 3600).contains(seconds) else { throw DaemonError.malformedMessage }
        case let .reportWiFiNetwork(observation):
            guard observation.isWellFormed else { throw DaemonError.malformedMessage }
        default: break
        }
    }
}
