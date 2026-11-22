// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Foundation
    import Testing
    import WGEXCore
    @testable import WGEXDaemonCore
    import WGEXDaemonCoreTesting
    import WGEXDaemonProtocol
    import WGEXEngineInterface

    /// M1-47: the injected sleep and wake reach the controller through `LabPowerInjector` and exercise the existing wake path
    /// (`PowerMonitorModel`, `TunnelController.powerChanged`) on the fakes and the manual clock. These tests document that path;
    /// none of them changes it.
    @Suite(.timeLimit(.minutes(1)))
    private struct LabPowerInjectionControllerTests {
        /// The rig: a started tunnel with a fresh handshake, and the wrapper over a fake IOKit monitor with a manual trigger.
        private struct Rig {
            let harness: ControllerHarness
            let generation: Generation
            let peer: PublicKey
            let trigger = ManualPowerTrigger()
            let lines = InjectedLines()
            let injector: LabPowerInjector

            init() async throws {
                harness = try ControllerHarness(); try await harness.install()
                generation = try await harness.start()
                peer = try #require(harness.profile.peers.first?.publicKey)
                await harness.controller.consume(.handshakeCompleted(peer: peer, at: harness.clock.wallNow), generation: generation)
                let (trigger, lines) = (trigger, lines)
                injector = LabPowerInjector(
                    inner: FakePowerMonitor(), trigger: trigger, isLabHost: { true }, log: { lines.record($0) },
                )
            }

            /// Hands one event, as the merged stream delivered it, to the controller exactly as `DaemonNetworkMonitoring` does.
            func apply(_ delivered: PowerEvent?, expecting event: PowerEvent) async throws {
                #expect(delivered == event)
                try await harness.controller.powerChanged(event)
            }

            /// pf calls made since `offset`; every one of them must be an enforcing policy.
            func policyCalls(since offset: Int) -> [String] {
                harness.trace.calls.dropFirst(offset).filter { $0.hasPrefix("pf.") }
            }
        }

        private static let nonEnforcing: Set = [
            "pf.disconnected",
            "pf.disconnecting",
            "pf.error",
            "pf.captive",
            "pf.lockdown",
            "pf.release",
        ]

        @Test
        func `releasing a pf reference is a non-enforcing operation`() {
            #expect(Self.nonEnforcing.contains("pf.release"))
        }

        @Test
        func `an injected 130 s sleep forces a handshake, reasserts blocked and protects again after the handshake`() async throws {
            let rig = try await Rig()
            var events = try await rig.injector.start().makeAsyncIterator()
            #expect(await rig.harness.controller.status.phase == .active(rig.generation))
            #expect(await rig.harness.controller.status.protection == .protected)
            let offset = rig.harness.trace.calls.count
            rig.trigger.fire(.sleep); try await rig.apply(events.next(), expecting: .sleep)
            #expect(await rig.harness.controller.status.protection == .protected, "the sleep alone changes nothing")
            #expect(!rig.harness.trace.calls.dropFirst(offset).contains("engine.handshake"))
            rig.harness.clock.advance(.seconds(130))
            rig.trigger.fire(.wake); try await rig.apply(events.next(), expecting: .wake)
            let calls = Array(rig.harness.trace.calls.dropFirst(offset))
            #expect(calls.contains("engine.bump")); #expect(calls.contains("engine.handshake")); #expect(!calls.contains("engine.down"))
            #expect(await rig.harness.controller.status.phase == .reasserting(rig.generation, reason: .wake))
            #expect(await rig.harness.controller.status.protection == .blocked)
            let policy = await rig.harness.ports.policy
            guard case .connecting = policy else { Issue.record("policy after the forced handshake is \(policy)"); return }
            await rig.harness.controller.consume(
                .handshakeCompleted(peer: rig.peer, at: rig.harness.clock.wallNow),
                generation: rig.generation,
            )
            #expect(await rig.harness.controller.status.phase == .active(rig.generation))
            #expect(await rig.harness.controller.status.protection == .protected)
            let policyCalls = rig.policyCalls(since: offset)
            #expect(!policyCalls.isEmpty)
            #expect(Set(policyCalls).isDisjoint(with: Self.nonEnforcing), "pf policy calls: \(policyCalls)")
            #expect(rig.lines.all == ["lab power inject sleep", "lab power inject wake"])
            await rig.injector.stop()
        }

        @Test
        func `an injected 3 s sleep with a fresh handshake forces nothing and changes no protection`() async throws {
            let rig = try await Rig()
            var events = try await rig.injector.start().makeAsyncIterator()
            let offset = rig.harness.trace.calls.count
            rig.trigger.fire(.sleep); try await rig.apply(events.next(), expecting: .sleep)
            rig.harness.clock.advance(.seconds(3))
            rig.trigger.fire(.wake); try await rig.apply(events.next(), expecting: .wake)
            let calls = Array(rig.harness.trace.calls.dropFirst(offset))
            #expect(calls.contains("engine.bump"), "wake still bumps sockets")
            #expect(!calls.contains("engine.handshake"), "no forced handshake while the handshake is fresh")
            #expect(!calls.contains("engine.down"))
            #expect(rig.policyCalls(since: offset).isEmpty, "no pf change: \(rig.policyCalls(since: offset))")
            #expect(await rig.harness.controller.status.phase == .active(rig.generation))
            #expect(await rig.harness.controller.status.protection == .protected)
            #expect(rig.lines.all == ["lab power inject sleep", "lab power inject wake"])
            await rig.injector.stop()
        }

        @Test
        func `the injector feeds the merged lifecycle stream: a 130 s injected sleep reasserts blocked`() async throws {
            let rig = try await Rig()
            let monitoring = DaemonNetworkMonitoring(
                controller: rig.harness.controller, routes: FakeRouteMonitor(), underlay: FakeUnderlayMonitor(), power: rig.injector,
                login: FakeLoginSessionMonitor(), ownPID: 123, clock: rig.harness.clock,
                readUnderlay: { UnderlayEvent(snapshot: ControllerHarness.underlay, satisfied: true) },
            )
            try await monitoring.start()
            let statuses = await rig.harness.controller.statusUpdates()
            rig.trigger.fire(.sleep)
            // Sleep and wake share one lifecycle kind with a latest-state revision: a wake received before the sleep was applied
            // supersedes it, and an unknown sleep length forces the handshake. The handshake is also 130 s old on the wall clock.
            // Either order therefore forces it, which is what this wiring test asserts; the ordered cases are the two above.
            rig.harness.clock.advance(.seconds(130))
            rig.trigger.fire(.wake)
            for await status in statuses {
                if case .reasserting = status.phase {
                    #expect(status.protection == .blocked)
                    break
                }
            }
            #expect(rig.harness.trace.calls.contains("engine.handshake"))
            await monitoring.stop()
            #expect(rig.trigger.stops == 1)
        }
    }
#endif
