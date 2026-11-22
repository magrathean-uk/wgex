// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import SwiftUI
import Synchronization
import Testing
@testable import WGEX
import WGEXCore
import WGEXProfileStore

@MainActor
private struct WGEXiOSUnitTests {
    @Test(arguments: FakeScenario.allCases)
    func `scenario argument selects only known cases`(_ scenario: FakeScenario) {
        #expect(FakeScenario.parse(arguments: ["app", "-WGEXFakeScenario", scenario.rawValue]) == scenario)
    }

    @Test(arguments: [[], ["-WGEXFakeScenario"], ["-WGEXFakeScenario", "bogus"]])
    func `missing and malformed scenarios are ignored`(_ arguments: [String]) {
        #expect(FakeScenario.parse(arguments: arguments) == nil)
    }

    @Test
    func `device without launch flag leaves protection unknown and flags off`() {
        let model = AppModel(arguments: [], simulator: false, environment: [:])
        #expect(!model.usesFakeBackend)
        #expect(model.status.protection == .unknown)
        #expect(!model.featureFlags.relayTransports)
    }

    @Test(arguments: [true, false])
    func `fake launch flag and simulator compose isolated stores`(_ simulator: Bool) {
        let first = AppModel(arguments: ["-WGEXFakeBackend"], simulator: simulator)
        let second = AppModel(arguments: ["-WGEXFakeBackend"], simulator: simulator)
        #expect(first.backend != nil)
        #expect(first.usesFakeBackend)
        #expect(first.container != second.container)
        #expect(first.onDemand == .off)
        #expect(!first.protection.ios.includeAllNetworks)
        #expect(first.automaticFailover)
    }

    @Test(arguments: [true, false])
    func `appearance overrides require a fake session`(_ simulator: Bool) {
        let model = AppModel(arguments: ["-WGEXAppearance", "dark", "-WGEXFakeBackend"], simulator: simulator)
        #expect(model.appearanceOverride == .dark)
        let real = AppModel(arguments: ["-WGEXAppearance", "dark"], simulator: simulator, environment: [:])
        #expect(real.appearanceOverride == nil)
    }

    @Test
    func `paste review stores only after confirmation and supports deletion`() async throws {
        let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        defer { try? FileManager.default.removeItem(at: model.container) }
        model.prepareFixture()
        #expect(model.review != nil)
        #expect(model.profiles.isEmpty)
        await model.confirmImport()
        let profile = try #require(model.profiles.first)
        #expect(model.review == nil)
        #expect(try await model.store.list().count == 1)
        await model.toggleConnection()
        let updates = try #require(model.backend).statusUpdates()
        var iterator = updates.makeAsyncIterator()
        #expect(await iterator.next()?.protection == .protected)
        await model.deleteProfiles(at: IndexSet(integer: 0))
        #expect(model.profiles.isEmpty)
        #expect(try await model.store.list().isEmpty)
        #expect(profile.name == "Imported profile")
    }

    @Test
    func `feature flags round trip through settings`() async throws {
        let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        defer { try? FileManager.default.removeItem(at: model.container) }
        model.featureFlags.relayTransports = true
        await model.savePreferences()
        #expect(try await model.store.loadSettings().app.featureFlags.relayTransports)
    }
}

// The fake backend links only into Debug and Lab builds; Release never imports WGEXTesting.
#if DEBUG || WGEX_LAB_BUILD
    import WGEXNEClient
    import WGEXTesting
    import WGEXUI

    /// Apply progress around the backend's install, which returns only once the edit has finished applying (M06-T02).
    @MainActor @Suite(.serialized)
    private struct IOSTunnelApplyTests {
        private struct Rig {
            let model: AppModel
            let fake: FakeTunnelBackend
            let gate: InstallGate
            let runner: Task<Void, Never>
        }

        private func rig(_ names: [String] = ["Home"]) async throws -> Rig {
            let (model, fake, runner) = try await TunnelListSupport.rig(names)
            let gate = InstallGate(fake: fake)
            model.installProfile = { try await gate.install($0) }
            return Rig(model: model, fake: fake, gate: gate, runner: runner)
        }

        private func finish(_ rig: Rig) async {
            await rig.gate.open()
            await TunnelListSupport.finish(rig.model, rig.runner)
        }

        private func move(_ rig: Rig, to phase: TunnelPhase) async throws {
            var next = rig.fake.currentStatus
            next.phase = phase
            next.protection = AppModel.isActive(phase) ? .protected : .blocked
            rig.fake.publish(next)
            try await TunnelListSupport.until { rig.model.status.phase == phase }
        }

        /// Starts Home, then saves an edit of it whose install the gate holds; the edit's task is returned.
        private func editRunning(_ rig: Rig, name: String = "Home renamed", start: Bool = true) async throws -> Task<Void, Never> {
            let model = rig.model
            let home = try #require(model.profiles.first)
            if start {
                await model.setTunnel(home.id, on: true)
                try await TunnelListSupport.until { model.status.phase == .active(Generation(rawValue: 1)) }
            }
            await model.openEditor(home)
            let editor = try #require(model.editor)
            var renamed = try editor.validatedProfile()
            renamed.name = name
            let held = await rig.gate.waiting
            let edit = Task { await model.commitEdit(renamed, model: editor) }
            try await TunnelListSupport.eventually { await rig.gate.waiting == held + 1 }
            #expect(model.applyingProfileID == home.id)
            return edit
        }

        @Test
        func `progress stays through a delayed restart until the install confirms the reconnect`() async throws {
            let rig = try await rig()
            let model = rig.model
            let home = try #require(model.profiles.first).id
            let edit = try await editRunning(rig)
            // The restart's own disconnect is expected; no window of any length ends the progress.
            try await move(rig, to: .stopping(Generation(rawValue: 1), reason: .userRequested))
            try await move(rig, to: .idle)
            try await Task.sleep(for: .milliseconds(400))
            #expect(model.applyingProfileID == home)
            #expect(model.operationMessage == nil)
            try await move(rig, to: .preparing(Generation(rawValue: 2)))
            try await move(rig, to: .active(Generation(rawValue: 2)))
            try await Task.sleep(for: .milliseconds(400))
            #expect(model.applyingProfileID == home)
            await rig.gate.release()
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == nil)
            #expect(model.isTunnelOn(home))
            #expect(model.profiles.first?.name == "Home renamed")
            await finish(rig)
        }

        @Test
        func `an in-place apply that never leaves active ends only when its install returns`() async throws {
            let rig = try await rig()
            let model = rig.model
            let home = try #require(model.profiles.first).id
            let edit = try await editRunning(rig)
            try await Task.sleep(for: .milliseconds(400))
            #expect(model.applyingProfileID == home)
            await rig.gate.release()
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == nil)
            await finish(rig)
        }

        @Test
        func `a reconnect failure ends the progress with its message`() async throws {
            let rig = try await rig()
            let model = rig.model
            let home = try #require(model.profiles.first).id
            let edit = try await editRunning(rig)
            try await move(rig, to: .idle)
            #expect(model.applyingProfileID == home)
            #expect(model.operationMessage == nil)
            await rig.gate.release(throwing: NEManagerClient.reconnectFailure)
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == "The edited tunnel could not reconnect. Retry.")
            #expect(model.profiles.first?.name == "Home")
            await finish(rig)
        }

        @Test
        func `the deadline reports an unconfirmed outcome and a late completion keeps it`() async throws {
            let rig = try await rig()
            let model = rig.model
            model.applyDeadline = .milliseconds(300)
            let edit = try await editRunning(rig)
            try await move(rig, to: .idle)
            try await TunnelListSupport.until { model.applyingProfileID == nil }
            let unconfirmed = "Applying changes could not be confirmed. Check the tunnel status and retry."
            #expect(model.operationMessage == unconfirmed)
            await rig.gate.release()
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == unconfirmed)
            await finish(rig)
        }

        @Test
        func `a switch to another tunnel interrupts the apply`() async throws {
            let rig = try await rig(["Home", "Office"])
            let model = rig.model
            let office = model.profiles[1].id
            let edit = try await editRunning(rig)
            var external = rig.fake.currentStatus
            external.phase = .active(Generation(rawValue: 9))
            external.protection = .protected
            external.activeProfileID = office
            rig.fake.publish(external)
            try await TunnelListSupport.until { model.applyingProfileID == nil }
            let interrupted = "Applying changes was interrupted. Check the tunnel status and retry."
            #expect(model.operationMessage == interrupted)
            #expect(model.isTunnelOn(office))
            // The backend's install ends as cancelled afterwards; the outcome already shown stays.
            await rig.gate.release(throwing: TunnelError.cancelled)
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == interrupted)
            await finish(rig)
        }

        @Test
        func `a cancelled install shows the interrupted outcome`() async throws {
            let rig = try await rig()
            let model = rig.model
            let edit = try await editRunning(rig)
            await rig.gate.release(throwing: TunnelError.cancelled)
            await edit.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == "Applying changes was interrupted. Check the tunnel status and retry.")
            await finish(rig)
        }

        @Test
        func `a late completion never clears a newer edit`() async throws {
            let rig = try await rig()
            let model = rig.model
            let home = try #require(model.profiles.first).id
            let first = try await editRunning(rig, name: "Home first")
            let second = try await editRunning(rig, name: "Home second", start: false)
            await rig.gate.release(keepHolding: true)
            await first.value
            #expect(model.applyingProfileID == home)
            #expect(model.operationMessage == nil)
            await rig.gate.release()
            await second.value
            #expect(model.applyingProfileID == nil)
            #expect(model.operationMessage == nil)
            #expect(model.profiles.first?.name == "Home second")
            await finish(rig)
        }
    }

    /// Holds each install until the test releases it, then hands it to the fake or throws. Once opened, installs pass
    /// straight through (the rollback install after a failure, the rig's teardown).
    internal actor InstallGate {
        private let fake: FakeTunnelBackend
        private var held: [CheckedContinuation<(any Error & Sendable)?, Never>] = []
        private var holding = true

        internal init(fake: FakeTunnelBackend) {
            self.fake = fake
        }

        internal var waiting: Int {
            held.count
        }

        internal func install(_ profile: TunnelProfile) async throws {
            if holding, let error = await withCheckedContinuation({ held.append($0) }) {
                throw error
            }
            try await fake.install(profile)
        }

        /// Releases the oldest held install.
        internal func release(throwing error: (any Error & Sendable)? = nil, keepHolding: Bool = false) {
            holding = keepHolding
            guard !held.isEmpty else { return }
            held.removeFirst().resume(returning: error)
        }

        internal func open() {
            holding = false
            for continuation in held {
                continuation.resume(returning: nil)
            }
            held.removeAll()
        }
    }

    /// The app-wide on-demand policy of an earlier `ios-shell.json` moves onto the profile it was applied to (M06-T06).
    @MainActor @Suite(.serialized)
    private struct IOSPreferencesMigrationTests {
        /// The preferences file as earlier versions wrote it, with the global on-demand policy.
        private struct LegacyShellPreferences: Codable {
            var onboardingComplete: Bool
            var profileOrder: [UUID]
            var protection: ProtectionPolicy
            var onDemand: OnDemandPolicy
            var automaticFailover: Bool
        }

        /// Two stored profiles, Office selected, and the status loop stopped; the container is kept for the relaunch.
        private func seed() async throws -> (container: URL, home: UUID, office: UUID) {
            let (model, _, runner) = try await TunnelListSupport.rig(["Home", "Office"])
            let home = model.profiles[0].id, office = model.profiles[1].id
            for var profile in model.profiles {
                profile.onDemand = .always(exceptSSIDs: [])
                try await model.store.save(profile)
                model.replaceProfile(profile)
            }
            model.selectedProfileID = office
            await model.savePreferences()
            runner.cancel()
            await runner.value
            return (model.container, home, office)
        }

        private func writeLegacy(_ legacy: LegacyShellPreferences, to container: URL) throws {
            try JSONEncoder().encode(legacy).write(to: shellURL(container), options: .atomic)
        }

        private func shellURL(_ container: URL) -> URL {
            container.appendingPathComponent("ios-shell.json")
        }

        private func shellKeys(_ container: URL) throws -> Set<String> {
            let object = try JSONSerialization.jsonObject(with: Data(contentsOf: shellURL(container)))
            return try Set(#require(object as? [String: Any]).keys)
        }

        private func shellObject(_ container: URL) throws -> [String: Any] {
            let object = try JSONSerialization.jsonObject(with: Data(contentsOf: shellURL(container)))
            return try #require(object as? [String: Any])
        }

        /// A fresh launch on the same container, loaded; `install` replaces the backend's install before the launch.
        private func launch(
            _ container: URL, count: Int, install: (@Sendable (TunnelProfile) async throws -> Void)? = nil,
        ) async throws -> (AppModel, Task<Void, Never>) {
            let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true, container: container)
            if let install {
                model.installProfile = install
            }
            let runner = Task { await model.run() }
            try await TunnelListSupport.until { model.profiles.count == count && !model.statusHistory.isEmpty }
            return (model, runner)
        }

        private func stop(_ runner: Task<Void, Never>) async {
            runner.cancel()
            await runner.value
        }

        @Test
        func `an old global policy moves onto the profile it was applied to and the file still loads`() async throws {
            let (container, home, office) = try await seed()
            defer { try? FileManager.default.removeItem(at: container) }
            let legacy = OnDemandPolicy.wifiOnly(exceptSSIDs: ["Cafe"])
            try writeLegacy(LegacyShellPreferences(
                onboardingComplete: true, profileOrder: [office, home], protection: ProtectionPolicy(ipv6Policy: .tunnel),
                onDemand: legacy, automaticFailover: false,
            ), to: container)

            let (model, runner) = try await launch(container, count: 2)
            try await TunnelListSupport.until { (try? shellKeys(container).contains("onDemand")) == false }
            #expect(model.profiles.map(\.id) == [office, home])
            #expect(model.selectedProfileID == office)
            #expect(model.onboardingComplete)
            #expect(model.profiles.first { $0.id == office }?.onDemand == legacy)
            #expect(model.profiles.first { $0.id == home }?.onDemand == .always(exceptSSIDs: []))
            #expect(model.operationMessage == nil)
            let stored = try await ProfileStore(container: container).list()
            #expect(stored.first { $0.id == office }?.onDemand == legacy)
            #expect(stored.first { $0.id == home }?.onDemand == .always(exceptSSIDs: []))
            #expect(try shellKeys(container) == ["onboardingComplete", "profileOrder", "protection", "automaticFailover"])
            await stop(runner)

            // A second launch reads the migrated file and keeps the per-tunnel policy.
            let (again, againRunner) = try await launch(container, count: 2)
            #expect(again.profiles.first { $0.id == office }?.onDemand == legacy)
            #expect(again.profiles.map(\.id) == [office, home])
            #expect(again.onboardingComplete)
            await stop(againRunner)
        }

        @Test
        func `a migration that cannot store keeps the old file for the next launch`() async throws {
            let (container, home, office) = try await seed()
            defer { try? FileManager.default.removeItem(at: container) }
            let legacy = OnDemandPolicy.off
            try writeLegacy(LegacyShellPreferences(
                onboardingComplete: true, profileOrder: [home, office], protection: ProtectionPolicy(ipv6Policy: .tunnel),
                onDemand: legacy, automaticFailover: true,
            ), to: container)
            let locked = try writableDirectories(container)
            for url in locked {
                try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: url.path)
            }
            let (model, runner) = try await launch(container, count: 2)
            try await TunnelListSupport.until { model.operationMessage != nil }
            #expect(model.profiles.map(\.id) == [home, office])
            #expect(try shellKeys(container).contains("onDemand"))
            await stop(runner)
            for url in locked {
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            }

            // The retry on the next launch completes the move.
            let (retry, retryRunner) = try await launch(container, count: 2)
            try await TunnelListSupport.until { (try? shellKeys(container).contains("onDemand")) == false }
            #expect(retry.profiles.first { $0.id == office }?.onDemand == legacy)
            #expect(try await ProfileStore(container: container).list().first { $0.id == office }?.onDemand == legacy)
            await stop(retryRunner)
        }

        @Test
        func `a failed install keeps the old policy pending until a relaunch installs it on the same tunnel`() async throws {
            let (container, home, office) = try await seed()
            defer { try? FileManager.default.removeItem(at: container) }
            let legacy = OnDemandPolicy.wifiOnly(exceptSSIDs: ["Cafe"])
            try writeLegacy(LegacyShellPreferences(
                onboardingComplete: true, profileOrder: [home, office], protection: ProtectionPolicy(ipv6Policy: .tunnel),
                onDemand: legacy, automaticFailover: true,
            ), to: container)
            let attempts = Mutex([UUID]())
            let (failing, failingRunner) = try await launch(container, count: 2) { profile in
                attempts.withLock { $0.append(profile.id) }
                throw TunnelError.backendUnavailable
            }
            try await TunnelListSupport.until { failing.operationMessage != nil }
            #expect(attempts.withLock { $0 } == [office])
            #expect(failing.operationMessage == AppModel.migrationFailedMessage)
            // The profile already carries the policy, yet it stays pending, with its tunnel, across preference saves.
            #expect(failing.profiles.first { $0.id == office }?.onDemand == legacy)
            failing.selectedProfileID = home
            await failing.savePreferences()
            var object = try shellObject(container)
            #expect(object["onDemand"] != nil)
            #expect(object["onDemandProfile"] as? String == office.uuidString)
            await stop(failingRunner)

            // The relaunch installs the tunnel it was applied to, not the one now selected, and the pending state clears.
            let (retry, retryRunner) = try await launch(container, count: 2)
            let fake = try #require(retry.backend as? FakeTunnelBackend)
            try await TunnelListSupport.until { (try? shellKeys(container).contains("onDemand")) == false }
            #expect(retry.selectedProfileID == home)
            #expect(fake.calls.contains(.install(office)))
            #expect(!fake.calls.contains(.install(home)))
            #expect(retry.operationMessage == nil)
            #expect(retry.pendingLegacyOnDemand == nil)
            #expect(retry.profiles.first { $0.id == office }?.onDemand == legacy)
            #expect(retry.profiles.first { $0.id == home }?.onDemand == .always(exceptSSIDs: []))
            object = try shellObject(container)
            #expect(object["onDemand"] == nil && object["onDemandProfile"] == nil)
            await stop(retryRunner)

            // A third launch has nothing left to move.
            let (settled, settledRunner) = try await launch(container, count: 2)
            let settledFake = try #require(settled.backend as? FakeTunnelBackend)
            #expect(!settledFake.calls.contains(.install(office)))
            await stop(settledRunner)
        }

        @Test
        func `a legacy policy whose profile is gone is dropped and the rest still loads`() async throws {
            let (container, home, office) = try await seed()
            defer { try? FileManager.default.removeItem(at: container) }
            // Every profile is deleted, so the old policy has no profile to move onto.
            let (model, runner) = try await launch(container, count: 2)
            await model.deleteProfiles(at: IndexSet([0, 1]))
            #expect(model.profiles.isEmpty)
            await stop(runner)
            try writeLegacy(LegacyShellPreferences(
                onboardingComplete: true, profileOrder: [home, office], protection: ProtectionPolicy(ipv6Policy: .tunnel),
                onDemand: .cellularOnly, automaticFailover: true,
            ), to: container)
            let (empty, emptyRunner) = try await launch(container, count: 0)
            try await TunnelListSupport.until { (try? shellKeys(container).contains("onDemand")) == false }
            #expect(empty.onboardingComplete)
            #expect(empty.operationMessage == nil)
            await stop(emptyRunner)
        }

        /// The container and every directory under it, so neither the store nor the preferences file can be written.
        private func writableDirectories(_ container: URL) throws -> [URL] {
            var result = [container]
            let enumerator = FileManager.default.enumerator(at: container, includingPropertiesForKeys: [.isDirectoryKey])
            while let url = enumerator?.nextObject() as? URL {
                if try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true {
                    result.append(url)
                }
            }
            return result
        }
    }

#endif
