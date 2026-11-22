// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private struct MacUIWorkTests {
        @Test func `termination before preferences load cannot overwrite saved preferences with defaults`() async {
            var writes = 0
            let model = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(savePreferences: { _ in writes += 1 }),
            ))
            let work = MacUIWork(shell: model, announce: { _ in })
            await work.flushPreferences()
            #expect(writes == 0)
        }

        @Test func `quit flush persists the latest snapshot once`() async {
            var saved: [MacPreferences] = []
            let model = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(savePreferences: { saved.append($0) }),
            ))
            let work = MacUIWork(shell: model, announce: { _ in })
            work.observePreferences()
            model.preferences.hideDockIcon = true
            model.preferences.onboardingComplete = true
            await work.flushPreferences()
            #expect(saved == [model.preferences])
            await work.flushPreferences()
            #expect(saved.count == 1)
            work.stop()
        }

        @Test(.timeLimit(.minutes(1)))
        func `termination flush joins the current write and persists a newer snapshot serially`() async {
            var snapshots: [MacPreferences] = []
            let (started, didStart) = AsyncStream<Void>.makeStream()
            let (releases, release) = AsyncStream<Void>.makeStream()
            let model = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(savePreferences: {
                    snapshots.append($0)
                    didStart.yield(())
                    if snapshots.count == 1 {
                        var gate = releases.makeAsyncIterator()
                        await gate.next()
                    }
                }),
            ))
            let work = MacUIWork(shell: model, announce: { _ in })
            work.observePreferences()
            model.preferences.hideDockIcon = true
            let first = Task { await work.flushPreferences() }
            var iterator = started.makeAsyncIterator()
            await iterator.next()
            model.preferences.onboardingComplete = true
            let termination = Task { await work.flushPreferences() }
            release.yield(())
            await first.value
            await termination.value
            #expect(snapshots.count == 2)
            #expect(snapshots.last == model.preferences)
            work.stop()
            didStart.finish()
            release.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `onboarding completion saves without waiting for the debounce clock`() async {
            var writes: [MacPreferences] = []
            let (saved, continuation) = AsyncStream<Void>.makeStream()
            let model = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(savePreferences: { writes.append($0); continuation.yield(()) }),
            ))
            let work = MacUIWork(shell: model, clock: .init(sleep: { _ in
                Issue.record("Onboarding completion must not wait for a debounce")
                throw CancellationError()
            }), announce: { _ in })
            work.observePreferences()
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 1))
            model.onboardingStep = .backgroundService
            await model.advanceOnboarding()
            var iterator = saved.makeAsyncIterator()
            await iterator.next()
            #expect(writes.count == 1)
            #expect(writes.first?.onboardingComplete == true)
            work.stop()
            continuation.finish()
        }

        @Test(.timeLimit(.minutes(1)))
        func `failed onboarding persistence remains pending for the next explicit flush`() async {
            var fail = true
            var writes: [MacPreferences] = []
            let model = MacShellModel(dependencies: .init(
                backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true,
                operations: .init(savePreferences: {
                    if fail {
                        throw TunnelError.permissionDenied
                    }
                    writes.append($0)
                }),
            ))
            let work = MacUIWork(shell: model, announce: { _ in })
            work.observePreferences()
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 1))
            model.revisit(.backgroundService)
            await model.advanceOnboarding()
            #expect(writes.isEmpty)
            #expect(model.operationMessage != nil)
            fail = false
            await work.flushPreferences()
            #expect(writes.last?.onboardingComplete == true)
            work.stop()
        }

        @Test(.timeLimit(.minutes(1)))
        func `one composition announces verdict and toast changes`() async {
            let now = Date()
            let model = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                status: .init(phase: .active(.init(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: []),
                now: now,
            )
            let (messages, continuation) = AsyncStream<String>.makeStream()
            let work = MacUIWork(shell: model, announce: { continuation.yield($0) })
            work.observePreferences()
            work.observePreferences()
            var iterator = messages.makeAsyncIterator()
            model.receive(.init(phase: .idle, protection: .unknown, transport: nil, health: .idle, recentEvents: []), at: now)
            #expect(await iterator.next() == model.designPresentation.accessibilityLabel)
            model.reportImportFailure()
            #expect(await iterator.next() == model.operationMessage)
            work.stop()
            continuation.finish()
            #expect(await iterator.next() == nil)
        }
    }
#endif
