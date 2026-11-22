// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonClient
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// M05-T07: the daemon's `uninstall(purgeState:)`, driven through the XPC composition the app and CLI use, against the host
/// fakes only.
private struct UninstallTests {
    @Test
    func `an active tunnel with the kill switch engaged ends with nothing behind it, in the fixed step order`() async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        let mark = harness.trace.calls.count
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        try await Self.expectNothingLeft(harness)
        let record = try #require(harness.journal.snapshot().uninstall)
        #expect(record.completed && !record.purgeState)
        #expect(record.finished == UninstallStep.allCases.filter { $0 != .purgeState })
        // The kill switch is released before any storage step, and the stop ran through the normal path.
        let calls = Array(harness.trace.calls.dropFirst(mark))
        let released = try #require(calls.lastIndex(of: "pf.release"))
        #expect(try #require(calls.lastIndex(of: "pf.disconnected")) < released)
        #expect(try #require(calls.firstIndex(of: "engine.shutdown")) < released)
        #expect(try #require(calls.firstIndex(of: "secrets.removeAll")) > released)
        #expect(try #require(calls.firstIndex(of: "bundles.removeAll")) > (calls.firstIndex(of: "secrets.removeAll") ?? .max))
        #expect(try #require(calls.firstIndex(of: "key.remove")) > (calls.firstIndex(of: "bundles.removeAll") ?? .max))
        let telemetry = try await Self.telemetry(fixture)
        #expect(telemetry.uninstall == UninstallProgress(completed: true, purgeState: false, pendingStep: nil))
        #expect(telemetry.status.phase == .idle && telemetry.status.activeProfileID == nil)
        // Done is done: a second request is answered at once.
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
    }

    @Test
    func `mutating requests meet the uninstall fence with a typed error, reads still answer`() async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let refused = Reply.error(.uninstallFailed(step: .admission))
        var lockdown = MacGlobalSettings.defaults; lockdown.lockdown = true
        #expect(try await fixture.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == refused)
        #expect(try await fixture.call(.setGlobalSettings(lockdown)) == refused)
        #expect(try await fixture.call(.armOnDemand(profileID: harness.profile.id, hasSecrets: false)) == refused)
        #expect(try await fixture.call(.prepareForUpdate) == refused)
        var wire = try ControllerHarness.bundle().wireBytes().withUnsafeBytes { Data($0) }
        defer { wire.resetBytes(in: 0 ..< wire.count) }
        #expect(try await fixture.call(
            .startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: true), secrets: wire,
        ) == refused)
        guard case .status = try await fixture.call(.status), case .secureInstall = try await fixture.call(.secureInstallStatus)
        else { throw HostTestError.injected }
        try await Self.expectNothingLeft(harness)
    }

    @Test(arguments: UninstallStep.allCases)
    func `each step failing leaves a typed error and a retry finishes`(step: UninstallStep) async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        await Self.failOnce(step, in: harness.controller)
        #expect(try await fixture.call(.uninstall(purgeState: true)) == .error(.uninstallFailed(step: step)))
        let steps = UninstallStep.allCases
        let index = try #require(steps.firstIndex(of: step))
        if step == .admission {
            // The fence never became durable; it holds in memory for this launch.
            #expect(harness.journal.snapshot().uninstall == nil)
        } else {
            let record = try #require(harness.journal.snapshot().uninstall)
            #expect(record.finished == Array(steps.prefix(index)) && !record.completed)
            #expect(try await Self.telemetry(fixture).uninstall == UninstallProgress(completed: false, purgeState: true, pendingStep: step))
        }
        let released = try #require(steps.firstIndex(of: .releaseReference))
        if index > released {
            // A failure after the release leaves the kill switch off.
            #expect(await harness.ports.policy == .disconnected)
            #expect(await harness.ports.token == nil)
        }
        #expect(try await fixture.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .error(
            .uninstallFailed(step: .admission),
        ))
        #expect(try await fixture.call(.uninstall(purgeState: true)) == .ok)
        try await Self.expectNothingLeft(harness)
        #expect(harness.journal.snapshot().uninstall?.finished == steps)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
    }

    @Test
    func `a port failure names its step and the retry resumes there`() async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        harness.trace.fail(at: "pf.release")
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .error(.uninstallFailed(step: .releaseReference)))
        #expect(harness.journal.snapshot().uninstall?.pendingStep == .releaseReference)
        #expect(try await harness.registry.ownerUID(for: harness.profile.id) == ControllerHarness.uid) // No storage step ran.
        let mark = harness.trace.calls.count
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let retried = Array(harness.trace.calls.dropFirst(mark))
        #expect(!retried.contains("engine.shutdown") && !retried.contains("pf.disconnected")) // Finished steps are not rerun.
        try await Self.expectNothingLeft(harness)
    }

    @Test
    func `keep removes the daemon's profiles, secrets and key but keeps the journal; purge keeps only the marker`() async throws {
        let kept = try await Self.active()
        var settings = MacGlobalSettings.defaults; settings.allowLAN = true; settings.lockdown = true
        #expect(try await kept.call(.setGlobalSettings(settings)) == .ok)
        // A sealed daemon copy of a profile secret, beside the bundle start-before-login keeps.
        let secret = SecretID(profileID: kept.harness.profile.id, kind: .privateKey, id: UUID())
        try await kept.harness.store.store(SecretBytes(zeroedCount: 32), for: secret)
        #expect(Self.stateFiles(kept.harness).contains { $0.hasPrefix("secrets/") && !$0.hasPrefix("secrets/bundles/") })
        #expect(try await kept.call(.uninstall(purgeState: false)) == .ok)
        #expect(kept.harness.trace.calls.contains("key.remove"))
        await #expect(throws: (any Error).self) { _ = try await kept.harness.store.load(secret) }
        #expect(Self.stateFiles(kept.harness) == ["journal.json"] || Self.stateFiles(kept.harness) == ["journal.json", "journal.log"])
        #expect(kept.harness.journal.snapshot().settings.allowLAN) // Kept: only lockdown is cleared.

        let purged = try await Self.active()
        #expect(try await purged.call(.setGlobalSettings(settings)) == .ok)
        #expect(try await purged.call(.uninstall(purgeState: true)) == .ok)
        #expect(Self.stateFiles(purged.harness) == ["journal.json"] || Self.stateFiles(purged.harness) == ["journal.json", "journal.log"])
        // Reduced to the marker and the generation fence: settings, history and bookkeeping are gone.
        let document = try DaemonJournal(directory: StateDirectory(root: purged.harness.root)).snapshot()
        var expected = DaemonJournalDocument()
        expected.generation = document.generation
        expected.uninstall = UninstallRecord(purgeState: true, finished: UninstallStep.allCases, completed: true)
        #expect(document == expected)
        #expect(try await Self.telemetry(purged).uninstall == UninstallProgress(completed: true, purgeState: true, pendingStep: nil))
    }

    @Test
    func `a kept uninstall asked again with purge runs only the purge`() async throws {
        let fixture = try await Self.active()
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let mark = fixture.harness.trace.calls.count
        #expect(try await fixture.call(.uninstall(purgeState: true)) == .ok)
        #expect(fixture.harness.trace.calls.dropFirst(mark).allSatisfy { call in !Self.networkCalls.contains { call.hasPrefix($0) } })
        #expect(fixture.harness.journal.snapshot().uninstall == UninstallRecord(
            purgeState: true, finished: UninstallStep.allCases, completed: true,
        ))
    }

    @Test
    func `after an uninstall every later launch is inert until a fresh install clears the marker`() async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let mark = harness.trace.calls.count
        let relaunched = try harness.replacementController()
        // What DaemonRuntime and the main loop call at a launch.
        await relaunched.markStartupRecovering()
        #expect(await !relaunched.shouldRetryStartup())
        try await relaunched.prepareStartupBlocking()
        try await relaunched.reconcileAtStartup()
        try await relaunched.verifyRecoveryProtection()
        try await relaunched.tick()
        try await relaunched.networkChanged(trigger: .periodic)
        #expect(harness.trace.calls.dropFirst(mark).allSatisfy { call in !Self.networkCalls.contains { call.hasPrefix($0) } })
        let second = CompositionFixture(harness: harness, controller: relaunched)
        try await second.connect()
        #expect(try await Self.telemetry(second).uninstall == UninstallProgress(completed: true, purgeState: false, pendingStep: nil))
        #expect(try await second.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .error(
            .uninstallFailed(step: .admission),
        ))
        // The fresh install: a verified secure install clears the marker, and the daemon serves again.
        guard case .secureInstall = try await second.call(.performSecureInstall) else { throw HostTestError.injected }
        #expect(try DaemonJournal(directory: StateDirectory(root: harness.root)).snapshot().uninstall == nil)
        #expect(await relaunched.uninstallProgress == nil)
        #expect(try await second.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .profileRevision(1))
    }

    @Test
    func `a crash mid-uninstall is refused at the next launch and the retry resumes and finishes`() async throws {
        let fixture = try await Self.active()
        let harness = fixture.harness
        await Self.failOnce(.daemonSecrets, in: harness.controller)
        #expect(try await fixture.call(.uninstall(purgeState: true)) == .error(.uninstallFailed(step: .daemonSecrets)))
        let mark = harness.trace.calls.count
        let relaunched = try harness.replacementController()
        await relaunched.markStartupRecovering()
        #expect(await !relaunched.shouldRetryStartup())
        try await relaunched.prepareStartupBlocking()
        try await relaunched.reconcileAtStartup()
        #expect(harness.trace.calls.dropFirst(mark).isEmpty)
        let second = CompositionFixture(harness: harness, controller: relaunched)
        try await second.connect()
        #expect(try await Self.telemetry(second).uninstall?.pendingStep == .daemonSecrets)
        #expect(try await second.call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .error(
            .uninstallFailed(step: .admission),
        ))
        // Before every step is done, a secure install does not end the uninstall.
        #expect(try await second.call(.performSecureInstall) == .error(.uninstallFailed(step: .admission)))
        #expect(try await second.call(.uninstall(purgeState: false)) == .ok)
        let record = try DaemonJournal(directory: StateDirectory(root: harness.root)).snapshot().uninstall
        #expect(record?.completed == true && record?.purgeState == true) // The purge asked first is never dropped.
        #expect(Self.stateFiles(harness) == ["journal.json"] || Self.stateFiles(harness) == ["journal.json", "journal.log"])
    }

    @Test
    func `uninstall is admitted while the dispatcher is recovering`() async throws {
        let fixture = try await Self.active()
        await fixture.composition.dispatcher.setRecovering(true)
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        try await Self.expectNothingLeft(fixture.harness)
    }

    @Test
    func `the admin right is required and the client carries its external form`() async throws {
        let harness = try ControllerHarness()
        let grant = Data([7, 7, 7])
        let composition = DaemonComposition(
            controller: harness.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }, hasAdminRight: { form, _ in form == grant }),
        )
        let transport = InMemoryXPCTransport(daemon: composition.dispatcher, peer: CompositionFixture.peer(ControllerHarness.uid))
        let client = DaemonClient(transport: transport, clientVersion: "test", clientBuild: 11)
        _ = try await client.connect()
        await #expect(throws: DaemonError.notAuthorised(.adminRightRequired)) {
            try await client.uninstall(purgeState: false, authorization: nil)
        }
        #expect(harness.journal.snapshot().uninstall == nil)
        await Self.failOnce(.removeRoutes, in: harness.controller)
        await #expect(throws: DaemonError.uninstallFailed(step: .removeRoutes)) {
            try await client.uninstall(purgeState: false, authorization: grant)
        }
        try await client.uninstall(purgeState: false, authorization: grant)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
    }

    @Test
    func `the marker survives a journal reopen and its steps follow the wire order`() throws {
        let harness = try ControllerHarness()
        let record = UninstallRecord(purgeState: false, finished: [.admission, .stopTunnel])
        try harness.journal.mutate(generation: nil) { $0.uninstall = record }
        #expect(try DaemonJournal(directory: StateDirectory(root: harness.root)).snapshot().uninstall == record)
        #expect(record.steps == UninstallStep.allCases.filter { $0 != .purgeState })
        #expect(record.pendingStep == .clearIntent)
        #expect(UninstallRecord(purgeState: true).steps == UninstallStep.allCases)
    }
}

private extension UninstallTests {
    /// Calls that would mean the daemon touched pf, routes, DNS or an engine.
    static let networkCalls = ["pf.", "routes.", "dns.", "engine.", "device."]

    /// A fixture with the profile installed, started and on start-before-login, and the kill switch (lockdown) engaged.
    static func active() async throws -> CompositionFixture {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        #expect(try await fixture.call(.setGlobalSettings(settings)) == .ok)
        #expect(try await fixture.call(.setStartBeforeLoginIntent(profileID: harness.profile.id, enabled: true)) == .ok)
        #expect(try await harness.store.storedBundleProfileIDs() == [harness.profile.id])
        return fixture
    }

    /// Fails `step` once, before its action runs.
    static func failOnce(_ step: UninstallStep, in controller: TunnelController) async {
        let armed = Mutex(true)
        await controller.setUninstallStepHook { current in
            if current == step, armed.withLock({ value in defer { value = false }; return value }) {
                throw HostTestError.injected
            }
        }
    }

    static func expectNothingLeft(_ harness: ControllerHarness) async throws {
        #expect(await harness.ports.policy == .disconnected)
        #expect(await harness.ports.ownedRoutes().isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        #expect(await harness.ports.token == nil)
        let document = harness.journal.snapshot()
        #expect(document.pfToken == nil && document.pfPolicy == .disconnected && document.intent == nil)
        #expect(document.resources.isEmpty && !document.settings.lockdown)
        #expect(try await harness.registry.ownerUID(for: harness.profile.id) == nil)
        #expect(try await harness.registry.bootIntent() == nil)
        #expect(try await harness.store.storedBundleProfileIDs().isEmpty)
    }

    static func telemetry(_ fixture: CompositionFixture) async throws -> StatusTelemetry {
        guard case let .statusTelemetry(telemetry) = try await fixture.call(.statusTelemetry) else { throw HostTestError.injected }
        return telemetry
    }

    /// Every regular file under the state root, relative to it.
    static func stateFiles(_ harness: ControllerHarness) -> [String] {
        let enumerator = FileManager.default.enumerator(at: harness.root, includingPropertiesForKeys: [.isRegularFileKey])
        var files: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            if (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                files.append(String(url.path.dropFirst(harness.root.path.count + 1)))
            }
        }
        return files.sorted()
    }
}

private struct UninstallWrappingKeyTests {
    @Test(arguments: [false, true])
    func `a never provisioned wrapping key does not block uninstall`(purge: Bool) async throws {
        let errors = UninstallKeyErrors([.notFound])
        let keyMissing = Mutex(false)
        let install = SecureInstall(system: FakeSecureInstallSystem(), validateKey: {
            if keyMissing.withLock({ $0 }) {
                throw SecretStoreError.notFound
            }
        })
        let harness = try ControllerHarness(secureInstall: install, secretsTransform: {
            UninstallKeyStore(base: $0, errors: errors)
        })
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        #expect(await install.status().state == .verified)
        keyMissing.withLock { $0 = true }
        #expect(try await fixture.call(.uninstall(purgeState: purge)) == .ok)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
        #expect(errors.values.withLock { $0.isEmpty })
        // The missing-key success still invalidates a previously cached key validation.
        #expect(await install.status().state == .needsAttention(.wrappingKeyUnavailable))
        #expect(try await fixture.call(.uninstall(purgeState: purge)) == .ok)
    }

    @Test(arguments: [SecretStoreError.locked, .unavailable, .duplicate, .system(-1)])
    func `other key errors fail each retry until removal succeeds`(error: SecretStoreError) async throws {
        let errors = UninstallKeyErrors([error, error, .notFound])
        let harness = try ControllerHarness(secretsTransform: { UninstallKeyStore(base: $0, errors: errors) })
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        try await harness.install()
        for _ in 0 ..< 2 {
            #expect(try await fixture.call(.uninstall(purgeState: true)) == .error(.uninstallFailed(step: .wrappingKey)))
            #expect(harness.journal.snapshot().uninstall?.pendingStep == .wrappingKey)
            #expect(harness.journal.snapshot().uninstall?.completed == false)
        }
        let mark = harness.trace.calls.count
        #expect(try await fixture.call(.uninstall(purgeState: true)) == .ok)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
        #expect(errors.values.withLock { $0.isEmpty })
        #expect(!harness.trace.calls.dropFirst(mark).contains("secrets.removeAll"))
        #expect(!harness.trace.calls.dropFirst(mark).contains("bundles.removeAll"))
    }
}

#if os(macOS)
    private struct SystemWrappingKeyRemovalTests {
        @Test
        func `absent system key succeeds without requiring the installed daemon`() throws {
            let calls = Mutex<[String]>([])
            let provider: any DaemonKeyRemoving = SystemDaemonKeyProvider(guardDaemon: {
                calls.withLock { $0.append("guard") }
                throw SecretStoreError.unavailable
            }, exists: {
                calls.withLock { $0.append("exists") }
                return false
            }, delete: { calls.withLock { $0.append("delete") } })
            try provider.removeWrappingKey()
            try provider.removeWrappingKey()
            #expect(calls.withLock { $0 } == ["exists", "exists"])
        }

        @Test
        func `present system key requires the installed daemon on every retry`() {
            let calls = Mutex<[String]>([])
            let provider: any DaemonKeyRemoving = SystemDaemonKeyProvider(guardDaemon: {
                calls.withLock { $0.append("guard") }
                throw SecretStoreError.unavailable
            }, exists: {
                calls.withLock { $0.append("exists") }
                return true
            }, delete: { calls.withLock { $0.append("delete") } })
            for _ in 0 ..< 2 {
                #expect(throws: SecretStoreError.unavailable) { try provider.removeWrappingKey() }
            }
            #expect(calls.withLock { $0 } == ["exists", "guard", "exists", "guard"])
        }

        @Test
        func `system key delete failure remains an error and can be retried`() throws {
            let calls = Mutex<[String]>([])
            let locked = Mutex(true)
            let provider: any DaemonKeyRemoving = SystemDaemonKeyProvider(guardDaemon: {
                calls.withLock { $0.append("guard") }
            }, exists: {
                calls.withLock { $0.append("exists") }
                return true
            }, delete: {
                calls.withLock { $0.append("delete") }
                if locked.withLock({ $0 }) {
                    throw SecretStoreError.locked
                }
            })
            for _ in 0 ..< 2 {
                #expect(throws: SecretStoreError.locked) { try provider.removeWrappingKey() }
            }
            locked.withLock { $0 = false }
            try provider.removeWrappingKey()
            #expect(calls.withLock { $0 } == Array(repeating: ["exists", "guard", "delete"], count: 3).flatMap { $0 })
        }

        @Test
        func `system key lookup errors are not treated as an absent key`() {
            let provider: any DaemonKeyRemoving = SystemDaemonKeyProvider(guardDaemon: {
                Issue.record("A failed lookup must not reach the installed-path guard")
            }, exists: { throw SecretStoreError.locked }, delete: {
                Issue.record("A failed lookup must not delete the key")
            })
            #expect(throws: SecretStoreError.locked) { try provider.removeWrappingKey() }
        }
    }
#endif

private final class UninstallKeyErrors: Sendable {
    let values: Mutex<[SecretStoreError]>

    init(_ errors: [SecretStoreError]) {
        values = Mutex(errors)
    }
}

private struct UninstallKeyStore: TunnelSecretStoring {
    let base: any TunnelSecretStoring
    let errors: UninstallKeyErrors

    func saveBundle(_ bytes: consuming SecretBytes, profileID: UUID) async throws {
        try await base.saveBundle(bytes, profileID: profileID)
    }

    func loadBundle(profileID: UUID) async throws -> SecretBytes {
        try await base.loadBundle(profileID: profileID)
    }

    func deleteBundle(profileID: UUID) async throws {
        try await base.deleteBundle(profileID: profileID)
    }

    func storedBundleProfileIDs() async throws -> [UUID] {
        try await base.storedBundleProfileIDs()
    }

    func removeAllSecrets() async throws {
        try await base.removeAllSecrets()
    }

    func removeAllBundles() async throws {
        try await base.removeAllBundles()
    }

    func removeWrappingKey() async throws {
        let next = errors.values.withLock { $0.isEmpty ? nil : $0.removeFirst() }
        if let next {
            throw next
        }
        try await base.removeWrappingKey()
    }
}
