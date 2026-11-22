// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// The uninstall of this daemon process (M05-T07).
internal struct UninstallRun {
    /// Raised before the durable marker is written and kept until a fresh secure install clears the marker.
    internal var fenced = false
    /// The running uninstall; a second request waits for it, then resumes from the journal.
    internal var task: Task<Void, any Error>?
    /// Host tests only: runs before each step, so any step can be made to fail.
    internal var stepHook: (@Sendable (UninstallStep) async throws -> Void)?
    /// The newest underlay event seen while fenced, recorded with no policy work and applied when a fresh install clears
    /// the marker, so the next start binds the real interface (M05-T16).
    internal var underlay: UnderlayEvent?
}

package extension TunnelController {
    /// What the uninstall fence admits: reads, the event subscription and the uninstall itself.
    static let uninstallAdmitted: Set<RequestKind> = [
        .hello, .status, .statistics, .logs, .diagnostics, .secureInstallStatus, .subscribeEvents, .uninstall,
    ]

    /// An uninstall is in progress, failed part-way or is done: this launch stays inert.
    var uninstallFenced: Bool {
        uninstallRun.fenced || journal.snapshot().uninstall != nil
    }

    /// The uninstall state `status` reports; nil when none was requested.
    var uninstallProgress: UninstallProgress? {
        journal.snapshot().uninstall?.progress
    }

    /// Refuses every mutating request while the fence is up, with `uninstallFailed(.admission)`. A secure install is the
    /// fresh install that clears a completed uninstall, so it is admitted once every step is done.
    func requireUninstallAdmission(_ kind: RequestKind) throws {
        guard uninstallFenced, !Self.uninstallAdmitted.contains(kind) else { return }
        if kind == .performSecureInstall, journal.snapshot().uninstall?.completed == true, uninstallRun.task == nil {
            return
        }
        throw DaemonFailure.uninstall(.admission)
    }

    /// Refuses lifecycle and policy work once the uninstall fence is up, with `uninstallFailed(.admission)`. Callers check it
    /// with no suspension before they commit, so a request admitted before the fence and suspended across it cannot re-arm
    /// protection after the uninstall released it.
    func requireNoUninstall() throws {
        if uninstallFenced {
            throw DaemonFailure.uninstall(.admission)
        }
    }

    /// Host tests only: runs `hook` before each step.
    func setUninstallStepHook(_ hook: (@Sendable (UninstallStep) async throws -> Void)?) {
        uninstallRun.stepHook = hook
    }

    /// Removes what the daemon holds, in the fixed `UninstallStep` order: the durable fence, the tunnel through the normal
    /// stop path, intent and lockdown, DNS, routes, the empty pf policy and the WGEX pf reference (the kill switch is off from
    /// here), then profiles, secrets, bundles, the wrapping key and, with `purgeState`, every other state file. A failed step
    /// throws `uninstallFailed` naming it; the journal keeps the steps already done, so a retry, in this launch or the next,
    /// resumes there. Returns only when every step is done. Authorisation stays with the dispatcher (the admin right).
    func uninstall(purgeState: Bool) async throws {
        while let running = uninstallRun.task {
            _ = await running.result
            if uninstallRun.task == running {
                uninstallRun.task = nil
            }
        }
        if let record = journal.snapshot().uninstall, record.completed, record.purgeState || !purgeState {
            return
        }
        let task = Task { [self] in try await runUninstall(purgeState: purgeState) }
        uninstallRun.task = task
        defer {
            if uninstallRun.task == task {
                uninstallRun.task = nil
            }
        }
        try await task.value
    }

    /// While fenced an underlay event is only recorded (the newest wins); no pf, route or DNS work runs (M05-T16).
    func recordFencedUnderlay(_ event: UnderlayEvent?) {
        if let event {
            uninstallRun.underlay = event
        }
    }

    /// A fresh secure install after a completed uninstall clears the marker, and the daemon serves requests again. The
    /// underlay event recorded while fenced is then applied, so the next start binds the real interface (M05-T16), and the
    /// runtime re-enters the startup sequence a normal launch runs: the current underlay is read and the monitors start
    /// (M05-T18). Returns whether that startup was begun; without a runtime the caller keeps its own retry.
    @discardableResult
    func clearUninstallAfterFreshInstall() async throws -> Bool {
        guard let record = journal.snapshot().uninstall, record.completed, uninstallRun.task == nil else { return false }
        try journal.mutate(generation: nil) { $0.uninstall = nil }
        uninstallRun.fenced = false
        acceptingRequests = true
        publish()
        if let event = uninstallRun.underlay {
            uninstallRun.underlay = nil
            do { try await networkChanged(trigger: .configuration, underlay: event) }
            catch { operationLog("fresh install underlay replay failed") }
        }
        guard let resume = startup.resume else { return false }
        await resume()
        return true
    }
}

private extension TunnelController {
    func runUninstall(purgeState: Bool) async throws {
        try await beginUninstall(purgeState: purgeState)
        try await uninstallStep(.stopTunnel) { try await $0.uninstallStopTunnel() }
        try await uninstallStep(.clearIntent) { try $0.uninstallClearIntent() }
        try await uninstallStep(.removeDNS) { controller in
            for resource in controller.journal.snapshot().resources {
                try await controller.ports.dns.remove(generation: resource.generation)
            }
        }
        try await uninstallStep(.removeRoutes) { try await $0.uninstallRemoveRoutes() }
        try await uninstallStep(.emptyPolicy) { controller in
            try await controller.applyPolicy(.disconnected, generation: controller.generation, recovery: true)
        }
        try await uninstallStep(.releaseReference) { try await $0.uninstallReleaseReference() }
        try await uninstallStep(.daemonProfiles) { controller in
            try await controller.registry.removeAllForUninstall()
            await controller.refreshArmedSelection()
        }
        try await uninstallStep(.daemonSecrets) { try await $0.secrets.removeAllSecrets() }
        try await uninstallStep(.onDemandBundles) { try await $0.secrets.removeAllBundles() }
        try await uninstallStep(.wrappingKey) { controller in
            do { try await controller.secrets.removeWrappingKey() }
            catch SecretStoreError.notFound { /* Covers stores that report a missing key as .notFound. */ }
            await controller.secureInstall.invalidate()
        }
        if journal.snapshot().uninstall?.purgeState == true {
            try await uninstallStep(.purgeState) { try $0.uninstallPurgeState() }
        }
        try completeUninstall()
    }

    /// The fence goes up in memory before anything can suspend, then durably; a newer start, arm, install or start-before-login
    /// enable admitted before it can no longer commit, and every startup stage still running is interrupted. Lifecycle and
    /// policy work already in the serial slot (a settings change, say) is drained, so it ends before the uninstall clears
    /// what it applied; work that would enter the slot later meets the fence (`requireNoUninstall`).
    func beginUninstall(purgeState: Bool) async throws {
        uninstallRun.fenced = true
        acceptingRequests = false
        admissions.revokeAll(
            [.start, .manualStart, .cutover, .restart, .onDemandStart, .arm, .install, .bootEnable], DaemonFailure.uninstall(.admission),
        )
        startup.controlID = UUID(); startup.bootStart = nil
        maintenanceState.securePolicyPending = false
        cancelBackgroundWork()
        await drainLifecycle()
        do {
            try await uninstallRun.stepHook?(.admission)
            try journal.mutate(generation: nil) { document in
                var record = document.uninstall ?? UninstallRecord(purgeState: purgeState)
                if purgeState, !record.purgeState {
                    record.purgeState = true; record.completed = false
                }
                if !record.finished.contains(.admission) {
                    record.finished.insert(.admission, at: 0)
                }
                document.uninstall = record
            }
        } catch {
            operationLog("uninstall step admission failed")
            publish()
            throw DaemonFailure.uninstall(.admission)
        }
        publish()
    }

    /// Runs `step` unless the journal records it done, then records it. Any failure becomes `uninstallFailed(step)`.
    func uninstallStep(_ step: UninstallStep, _ action: (isolated TunnelController) async throws -> Void) async throws {
        guard journal.snapshot().uninstall?.finished.contains(step) != true else { return }
        do {
            try await uninstallRun.stepHook?(step)
            try await action(self)
            try journal.mutate(generation: nil) { document in
                guard var record = document.uninstall else { throw DaemonFailure.uninstall(step) }
                if !record.finished.contains(step) {
                    record.finished.append(step)
                }
                document.uninstall = record
            }
        } catch {
            operationLog("uninstall step \(step.rawValue) failed")
            publish()
            throw DaemonFailure.uninstall(step)
        }
    }

    /// An armed or pending cutover trial is rolled back first, in the uninstall's own order: no boot-flag, bundle or pf step
    /// runs there, so the release steps still come before any storage step. Then the active or tearing-down tunnel stops
    /// through the normal stop path. The stop keeps the secrets: with the kill switch engaged its final policy still blocks,
    /// and a bundle deletion there would run, and could fail, before the release. The storage steps after the release remove
    /// every secret and bundle.
    func uninstallStopTunnel() async throws {
        try await rollbackCutoverForUninstall()
        var target = intended.map { (id: $0.profileID, uid: $0.ownerUID) }
        if target == nil, let id = pendingTeardownProfileID, let uid = try await registry.ownerUID(for: id) {
            target = (id, uid)
        }
        guard let target else { return }
        try await withCommand(.stop, profile: target.id, input: false) { admission in
            _ = try await stop(
                profileID: target.id, connectionUID: target.uid, reason: .uninstall, retainingSecrets: true, admission: admission,
            )
        }
    }

    func uninstallClearIntent() throws {
        if settings.lockdown {
            settings.lockdown = false
        }
        if intended != nil || journal.snapshot().intent != nil {
            _ = try reserve(intent: nil)
        }
        let cleared = settings
        try journal.mutate(generation: nil) {
            $0.intent = nil; $0.settings = cleared; $0.captiveWindow = nil; $0.cutover = nil; $0.loginSuspended = nil
        }
        pendingTeardownProfileID = nil
    }

    func uninstallRemoveRoutes() async throws {
        for resource in journal.snapshot().resources {
            try await ports.routes.removeRoutes(of: resource.generation)
            try await ports.routes.removeCanaryRoute(of: resource.generation)
            try await removeOwnedResources(resource) {}
        }
        try journal.mutate(generation: nil) { $0.resources = [] }
    }

    func uninstallReleaseReference() async throws {
        if let token = journal.snapshot().pfToken {
            try await ports.policy.releaseToken(token)
        }
        try journal.mutate(generation: nil) {
            $0.pfToken = nil; $0.pfBootSession = nil; $0.pfTokenPID = nil; $0.pfEnableAttempted = nil
        }
    }

    /// Every other state file goes; the journal keeps its generation (the fence for late continuations) and the marker.
    func uninstallPurgeState() throws {
        try journal.purgeStateFiles()
        try journal.mutate(generation: nil) { document in
            var purged = DaemonJournalDocument()
            purged.generation = document.generation
            purged.uninstall = document.uninstall
            document = purged
        }
    }

    func completeUninstall() throws {
        let record = journal.snapshot().uninstall
        do {
            try journal.mutate(generation: nil) { document in
                document.uninstall?.completed = true
                document.pendingSecretDeletions = []; document.lastGoodAddresses = [:]; document.protectionOwnerUID = nil
            }
        } catch {
            throw DaemonFailure.uninstall(record?.steps.last ?? .wrappingKey)
        }
        settings = journal.snapshot().settings
        needsRecovery = false
        startup.reconciliationPending = false; startup.secureInstallRegressed = false; startup.installWasVerified = false
        pendingTeardownProfileID = nil; lastProfileID = nil; policyProfileID = nil; protectionFailureReason = nil
        snapshot = .idle
        publish()
    }
}
