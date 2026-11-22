// SPDX-License-Identifier: MIT
#if os(macOS)
    import Testing
    import WGEXCore
    import WGEXDaemonCore
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct ControllerShellFreshnessTests {
        @Test
        func `a real controller remains unprotected and connectable twenty seconds after normal stop`() async throws {
            let fixture = try ControllerShellFixture()
            try await fixture.start()
            _ = try await fixture.controller.stop(profileID: fixture.profile.id, connectionUID: 501)
            let verification = await fixture.controller.status.verifiedAt
            fixture.clock.advance(20)
            try await fixture.controller.tick()
            try await fixture.refresh()
            #expect(fixture.shell.status.phase == .idle)
            #expect(fixture.shell.status.verifiedAt == verification)
            #expect(!fixture.shell.status.policyEnforcing)
            #expect(fixture.shell.presentation.verdict == .unprotected)
            #expect(fixture.shell.presentation.action == .connect)
            #expect(fixture.shell.canConnect)
            await fixture.close()
        }

        @Test
        func `a fresh real daemon with no tunnel needs no invented verification to connect`() async throws {
            let fixture = try ControllerShellFixture()
            fixture.clock.advance(20)
            try await fixture.controller.tick()
            try await fixture.refresh()
            #expect(fixture.shell.status.verifiedAt == nil)
            #expect(fixture.shell.status.protection == .unprotected)
            #expect(fixture.shell.presentation.action == .connect)
            #expect(fixture.shell.canConnect)
            await fixture.close()
        }

        @Test
        func `recovering controller renews real blocking verification after twenty seconds`() async throws {
            let fixture = try ControllerShellFixture()
            try fixture.journal.mutate(generation: nil) { $0.intent = .init(profileID: fixture.profile.id, ownerUID: 501) }
            try await fixture.controller.recoveryFailed(.resolverUnavailable)
            let previous = await fixture.controller.status.verifiedAt
            fixture.clock.advance(20)
            try await fixture.controller.verifyRecoveryProtection()
            try await fixture.refresh()
            #expect(fixture.shell.status.verifiedAt != previous)
            #expect(fixture.shell.status.verifiedAt == fixture.clock.wallNow)
            #expect(fixture.shell.status.protection == .blocked)
            #expect(fixture.shell.presentation.verdict == .blocked)
            #expect(fixture.shell.presentation.recoveryDetail == MacStrings.recoveryResolverUnavailable)
            await fixture.close()
        }

        @Test
        func `a thirty second real connect remains connecting with cancel while its heartbeat responds`() async throws {
            let gate = ControllerShellStartGate()
            let fixture = try ControllerShellFixture(steps: gate)
            let connecting = Task { try await fixture.start() }
            await gate.wait()
            fixture.clock.advance(30)
            try await fixture.refresh()
            #expect(fixture.shell.status.operationInFlight)
            #expect(fixture.shell.presentation.verdict == .connecting)
            #expect(fixture.shell.presentation.action == .cancel)
            await gate.release()
            try await connecting.value
            _ = try await fixture.controller.stop(profileID: fixture.profile.id, connectionUID: 501)
            await fixture.close()
        }

        @Test(arguments: [
            (TunnelPhase.idle, ProtectionAction.connect),
            (.active(.init(rawValue: 7)), .disconnect),
            (.preparing(.init(rawValue: 7)), .cancel),
            (.configuring(.init(rawValue: 7)), .cancel),
        ])
        func `known live phases keep controls when protection verification expires`(_ phase: TunnelPhase, _ action: ProtectionAction) {
            var status = TunnelStatus.unreported
            status.phase = phase; status.serviceResponding = true; status.verificationExpired = true
            let presentation = ProtectionPresentation(status: status)
            #expect(presentation.verdict == .unknown)
            #expect(presentation.action == action)
            #expect(!presentation.colour.isProtectionColour)
        }
    }
#endif
