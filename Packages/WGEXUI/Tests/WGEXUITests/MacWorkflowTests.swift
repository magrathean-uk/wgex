// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Security
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    @MainActor
    @Suite("M1-08 Mac workflows", .timeLimit(.minutes(1)))
    package struct MacWorkflowTests {
        private func shell(operations: MacShellOperations = MacShellOperations()) -> MacShellModel {
            MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(), service: FakeServiceController(initial: .enabled),
                simulated: true, operations: operations,
            ), profiles: [TunnelProfile(name: "Workflow")])
        }

        @Test package func `old preferences preserve each present key and ignore the retired automaticFailover`() throws {
            let decoded = try JSONDecoder().decode(MacPreferences.self, from: Data(
                #"{"onboardingComplete":true,"hideDockIcon":true,"automaticFailover":false}"#.utf8,
            ))
            #expect(decoded.onboardingComplete)
            #expect(decoded.hideDockIcon)
            #expect(decoded.global == .defaults)
            #expect(decoded.flags == .defaults)
        }

        @Test package func `secure install entry persists completion before Done and cancellation preserves state`() async {
            var saved: [MacPreferences] = []
            var cancelled = false
            var attempts = 0
            let model = shell(operations: MacShellOperations(
                savePreferences: { saved.append($0) },
                secureInstall: {
                    attempts += 1
                    if cancelled {
                        throw TunnelError.cancelled
                    }
                    return .verified
                }, refreshDaemon: { true },
            ))
            await model.refreshService()
            await model.verifySecureInstall()
            #expect(attempts == 1)
            #expect(model.secureInstall == .verified)
            #expect(saved.last?.onboardingComplete == true)
            cancelled = true
            await model.verifySecureInstall()
            #expect(model.secureInstall == .verified)
            #expect(model.operationMessage?.hasPrefix("Secure install was cancelled") == true)
        }

        @Test package func `settings use daemon acknowledgement and keep previous cache on failure`() async {
            var requests: [MacGlobalSettings] = []
            var fail = false
            let model = shell(operations: MacShellOperations(setGlobalSettings: {
                requests.append($0)
                if fail {
                    throw TunnelError.permissionDenied
                }
                var reply = $0
                reply.captiveWindowSeconds = 60
                return reply
            }))
            var proposal = MacGlobalSettings.defaults
            proposal.lockdown = true; proposal.allowLAN = false; proposal.notifications = false
            await model.setGlobalSettings(proposal)
            #expect(requests == [proposal])
            #expect(model.preferences.global.lockdown)
            #expect(!model.preferences.global.allowLAN)
            #expect(!model.preferences.global.notifications)
            #expect(model.preferences.global.captiveWindowSeconds == 60)
            fail = true
            await model.setGlobalSettings(.defaults)
            #expect(model.preferences.global.lockdown)
            #expect(model.operationMessage != nil)
        }

        @Test package func `activation notices approval and does not connect before registration`() async {
            let service = FakeServiceController()
            var connections = 0
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(), service: service, simulated: true,
                operations: MacShellOperations(refreshDaemon: { connections += 1; return true }),
            ))
            await model.applicationActivated()
            #expect(connections == 0)
            model.reportDaemonFailure()
            #expect(model.operationMessage == nil)
            service.transition(to: .requiresApproval)
            await model.applicationActivated()
            #expect(connections == 0)
            service.transition(to: .enabled)
            await model.applicationActivated()
            #expect(connections == 1)
            #expect(model.serviceState == .enabled)
            #expect(model.daemonRunning)
        }

        @Test package func `delete deactivates the active profile first and updates list only after success`() async throws {
            var deleted: [UUID] = []
            let backend = FakeTunnelBackend()
            backend.faults.arm("stop", error: TunnelError.timedOut)
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: FakeServiceController(initial: .enabled),
                simulated: true, operations: MacShellOperations(deleteProfile: { deleted.append($0.id) }),
            ), profiles: [TunnelProfile(name: "Workflow")])
            let profile = try #require(model.selectedProfile)
            model.receive(TunnelStatus(
                phase: .active(Generation(rawValue: 1)),
                protection: .protected,
                transport: nil,
                health: .idle,
                recentEvents: [],
            ), at: Date())
            let quick = MacIdleWait(attempts: 2) {}
            // SPEC 6.4: a failed deactivation deletes nothing and says why.
            await model.deleteProfile(profile, idleWait: quick)
            #expect(deleted.isEmpty)
            #expect(model.profiles.count == 1)
            #expect(model.operationMessage?.contains("could not be deactivated") == true)
            await model.deleteProfile(profile, idleWait: quick)
            #expect(backend.calls.filter { $0 == .stop(profile.id) }.count == 2)
            #expect(deleted == [profile.id])
            #expect(model.profiles.isEmpty)
        }

        @Test package func `every scene awaits the same preferences load and applies Dock policy`() async {
            let root = Self.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let gate = WorkflowGate()
            var loads = 0
            var dock: [Bool] = []
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, preferencesLoader: {
                loads += 1
                await gate.wait()
                var preferences = MacPreferences()
                preferences.onboardingComplete = true; preferences.hideDockIcon = true
                return preferences
            }, applyDockPolicy: { dock.append($0) })
            let first = Task { await app.start() }
            await gate.entered()
            var secondReturned = false
            let (secondEntered, didEnter) = AsyncStream<Void>.makeStream()
            let second = Task { didEnter.yield(()); await app.start(); secondReturned = true }
            var entries = secondEntered.makeAsyncIterator()
            await entries.next()
            #expect(!secondReturned)
            didEnter.finish()
            gate.release()
            await first.value; await second.value
            defer { app.stopObserving() }
            #expect(loads == 1)
            #expect(app.shell.preferences.onboardingComplete)
            #expect(dock == [true])
        }

        @Test package func `editor keeps dirty state until asynchronous save succeeds`() async throws {
            let parsed = try EditorFixtures.parsed()
            let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
            model.draft.name = "Changed"
            let gate = WorkflowGate()
            let task = Task { try await model.save { _, _ in await gate.wait() } }
            await gate.entered()
            #expect(model.isDirty)
            #expect(model.isSaving)
            gate.release()
            try await task.value
            #expect(!model.isDirty)
            #expect(!model.isSaving)
            model.draft.name = "Retry"
            await #expect(throws: TunnelError.permissionDenied) {
                try await model.save { _, _ in throw TunnelError.permissionDenied }
            }
            #expect(model.isDirty)
        }

        @Test package func `onboarding completion survives relaunch and step 2 Continue writes immediately`() async throws {
            let root = Self.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(
                arguments: ["-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { FakeServiceController(initial: .enabled) },
                applyDockPolicy: { _ in },
            )
            await app.start()
            await app.applicationActivated()
            await app.shell.verifySecureInstall()
            #expect(app.shell.onboardingStep == .welcome)
            #expect(try await MacPersistence(container: root, simulated: true).load().onboardingComplete)
            app.stopObserving()
            let relaunched = MacAppModel(
                arguments: ["-WGEXFakeBackend"], container: root,
                fakeServiceFactory: { FakeServiceController(initial: .enabled) }, applyDockPolicy: { _ in },
            )
            await relaunched.start()
            defer { relaunched.stopObserving() }
            #expect(relaunched.shell.preferences.onboardingComplete)
            relaunched.shell.preferences.onboardingComplete = false
            _ = await relaunched.shell.savePreferences()
            #expect(try await !MacPersistence(container: root, simulated: true).load().onboardingComplete)
            // Step 2 Continue, once the service runs, is the write that completes setup.
            await relaunched.applicationActivated()
            relaunched.shell.revisit(.backgroundService)
            await relaunched.shell.advanceOnboarding()
            #expect(relaunched.shell.onboardingStep == .addTunnel)
            #expect(try await MacPersistence(container: root, simulated: true).load().onboardingComplete)
        }

        @Test package func `Security cancellation has a distinct typed outcome`() throws {
            #expect(throws: TunnelError.cancelled) {
                try SystemSecureInstallAuthorisation.checkGrantResult(errAuthorizationCanceled)
            }
            try SystemSecureInstallAuthorisation.checkGrantResult(errAuthorizationSuccess)
        }

        package static func scratch() -> URL {
            FileManager.default.temporaryDirectory.appendingPathComponent("wgex-m1-08-\(UUID().uuidString)", isDirectory: true)
        }
    }

    @MainActor
    private final class WorkflowGate {
        private var waiting: CheckedContinuation<Void, Never>?
        private var arrival: CheckedContinuation<Void, Never>?
        func wait() async {
            await withCheckedContinuation { waiting = $0; arrival?.resume(); arrival = nil }
        }

        func entered() async {
            if waiting != nil {
                return
            }
            await withCheckedContinuation { arrival = $0 }
        }

        func release() {
            waiting?.resume(); waiting = nil
        }
    }
#endif
