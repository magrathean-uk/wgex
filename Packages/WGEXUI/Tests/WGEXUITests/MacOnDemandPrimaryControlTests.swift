// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXTesting
    @testable import WGEXUI

    /// Answers the handshake, the profile install and the control requests; records everything the client sends.
    private actor RecordingTransport: XPCTransport {
        private(set) var requests: [Request] = []

        func connect(callbacks _: XPCClientCallbacks) {}
        func invalidate() {}

        func send(_ envelope: Data, secrets _: Data?) async throws -> Data {
            let request = try Envelope.decode(envelope).body
            requests.append(request)
            switch request {
            case .hello:
                return try WireCodec.encode(Reply.hello(.init(
                    daemonVersion: "1", daemonBuild: 10, protocolVersion: Envelope.currentProtocolVersion, minimumClientBuild: 1,
                )))
            case .status: return try WireCodec.encode(Reply.status(.idle))
            case .profileRevision: return try WireCodec.encode(Reply.profileRevision(nil))
            case .installProfileCAS: return try WireCodec.encode(Reply.profileRevision(1))
            default: return try WireCodec.encode(Reply.ok)
            }
        }

        /// Control requests only: the install that precedes an arm and the handshake are not what these tests judge.
        var controlRequests: [Request] {
            requests.filter {
                switch $0 {
                case .armOnDemand, .disarmOnDemand, .startIntent, .stop, .stopCurrent: true
                default: false
                }
            }
        }
    }

    /// The two surfaces that carry the primary control (ADR-030 section 6 rule 1).
    private enum Surface: String, CaseIterable, Sendable {
        case window, menu
    }

    private enum Situation: String, Sendable {
        /// Has a rule, not armed, tunnel down.
        case disarmed
        /// Armed, tunnel down.
        case armedIdle
        /// Armed, tunnel up.
        case armedUp
        /// Not armed, tunnel up (a manual start, or kept up when the rule went off).
        case disarmedUp
    }

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacOnDemandPrimaryControlTests {
        private static let rule = OnDemandPolicy.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"])))

        private struct Harness {
            let model: MacShellModel
            let transport: RecordingTransport
            let client: DaemonClient
            let profile: TunnelProfile
        }

        private func makeHarness(_ situation: Situation, policy: OnDemandPolicy = rule) async -> Harness {
            var profile = TunnelProfile(name: "Home VPN")
            profile.onDemand = policy
            let transport = RecordingTransport()
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = MacShellModel(
                dependencies: .init(
                    backend: client, service: FakeServiceController(initial: .enabled), simulated: false,
                    operations: MacShellOperations(
                        errorCopy: MacAppErrorCopy.resolve,
                        armOnDemand: { profile in
                            try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await client.armOnDemand(profile.id) }
                        },
                        disarmOnDemand: { id in
                            try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await client.disarmOnDemand(id) }
                        },
                    ),
                ),
                profiles: [profile],
            )
            model.daemonHooks.continuousNow = { XPCClock.continuousSeconds }
            model.daemonHooks.stopCurrent = { try await client.stopCurrent() }
            model.receiveConnection(.connected(daemonBuild: 10))
            model.selectedProfileID = profile.id
            model.receive(status(situation, profile: profile), at: Date())
            return Harness(model: model, transport: transport, client: client, profile: profile)
        }

        private func status(_ situation: Situation, profile: TunnelProfile) -> TunnelStatus {
            var status = TunnelStatus.idle
            status.measuredAt = Date()
            status.measuredAtContinuous = XPCClock.continuousSeconds
            let up = situation == .armedUp || situation == .disarmedUp
            if up {
                status.phase = .active(Generation(rawValue: 1))
                status.protection = .protected
                status.activeProfileID = profile.id
            }
            if situation == .armedIdle || situation == .armedUp {
                status.onDemand = OnDemandStatus(
                    armedProfileID: profile.id, activated: false, network: .wifi, ssid: .known, decision: .connect,
                )
            }
            return status
        }

        private func label(_ surface: Surface, _ model: MacShellModel) -> String {
            surface == .window ? model.windowPrimaryControl.title : model.menuPrimaryControl.title
        }

        private func press(_ surface: Surface, _ model: MacShellModel) async {
            if surface == .window {
                await model.toggleConnection()
            } else {
                await model.toggleActiveConnection()
            }
        }

        // MARK: A profile with a rule arms and disarms

        @Test(arguments: Surface.allCases)
        func `a disarmed profile with a rule offers Enable on-demand and sends arm, never a start`(_ surface: Surface) async {
            let harness = await makeHarness(.disarmed)
            #expect(label(surface, harness.model) == MacStrings.enableOnDemand)
            #expect(harness.model.canConnect)
            #expect(harness.model.canToggleActiveConnection)
            await press(surface, harness.model)
            let requests = await harness.transport.controlRequests
            #expect(requests == [.armOnDemand(profileID: harness.profile.id, hasSecrets: false)])
            #expect(harness.model.operationMessage == nil)
            await harness.client.disconnect()
        }

        @Test(arguments: Surface.allCases)
        func `an armed profile whose tunnel is down offers Disable on-demand and sends disarm`(_ surface: Surface) async {
            let harness = await makeHarness(.armedIdle)
            #expect(label(surface, harness.model) == MacStrings.disableOnDemand)
            await press(surface, harness.model)
            let requests = await harness.transport.controlRequests
            #expect(requests == [.disarmOnDemand(profileID: harness.profile.id)])
            await harness.client.disconnect()
        }

        @Test(arguments: Surface.allCases)
        func `an armed profile whose tunnel is up offers Disable on-demand and deactivate and sends one disarm`(
            _ surface: Surface,
        ) async {
            let harness = await makeHarness(.armedUp)
            #expect(label(surface, harness.model) == MacStrings.disableOnDemandAndDeactivate)
            await press(surface, harness.model)
            // The daemon stops an intended profile on disarm (rule 2), so the app sends no stop of its own.
            let requests = await harness.transport.controlRequests
            #expect(requests == [.disarmOnDemand(profileID: harness.profile.id)])
            await harness.client.disconnect()
        }

        @Test(arguments: Surface.allCases)
        func `a tunnel that is up without arming can still be disconnected from the primary control`(_ surface: Surface) async {
            let harness = await makeHarness(.disarmedUp)
            #expect(label(surface, harness.model) == UserStrings.disconnect)
            await press(surface, harness.model)
            let requests = await harness.transport.controlRequests
            #expect(requests == [.stopCurrent(reason: .userRequested)])
            await harness.client.disconnect()
        }

        // MARK: Everything else keeps its action

        @Test(arguments: [OnDemandPolicy.off, .cellularOnly])
        func `a profile without a rule keeps Connect`(_ policy: OnDemandPolicy) async {
            let harness = await makeHarness(.disarmed, policy: policy)
            #expect(harness.model.windowPrimaryControl == .action(.connect))
            #expect(harness.model.menuPrimaryControl == .action(.connect))
            #expect(harness.model.windowPrimaryControl.title == UserStrings.connect)
            await harness.client.disconnect()
        }

        @Test
        func `a profile without a rule keeps Disconnect while its tunnel is up`() async {
            let harness = await makeHarness(.disarmedUp, policy: .off)
            #expect(harness.model.windowPrimaryControl == .action(.disconnect))
            #expect(harness.model.menuPrimaryControl.title == UserStrings.disconnect)
            await harness.client.disconnect()
        }

        @Test
        func `Check Again stays when the daemon has not reported, whatever the rule`() async {
            let harness = await makeHarness(.disarmed)
            harness.model.receive(.idle, at: Date())
            #expect(harness.model.windowPrimaryControl == .action(.checkAgain))
            #expect(harness.model.menuPrimaryControl == .action(.checkAgain))
            await harness.client.disconnect()
        }

        @Test
        func `a stopped service never offers arming`() async {
            let harness = await makeHarness(.disarmed)
            harness.model.receiveConnection(.disconnected(lastError: nil))
            #expect(!harness.model.windowPrimaryControl.armsOrDisarms)
            #expect(!harness.model.menuPrimaryControl.armsOrDisarms)
            await harness.client.disconnect()
        }

        // MARK: Gating while a command is in flight

        @Test(arguments: Surface.allCases)
        func `the arm control is unavailable while another control command is pending`(_ surface: Surface) async {
            let harness = await makeHarness(.disarmed)
            harness.model.pendingAction = .disconnecting
            #expect(label(surface, harness.model) == MacStrings.enableOnDemand)
            #expect(!harness.model.canConnect)
            #expect(!harness.model.canToggleActiveConnection)
            await press(surface, harness.model)
            #expect(await harness.transport.controlRequests.isEmpty)
            await harness.client.disconnect()
        }

        // MARK: A menu row

        @Test
        func `a menu row arms a profile with a rule and never starts it`() async {
            let other = TunnelProfile(name: "Other")
            let harness = await makeHarness(.disarmed)
            harness.model.profiles = [other, harness.profile]
            harness.model.selectedProfileID = other.id
            await harness.model.chooseFromMenu(harness.profile)
            #expect(harness.model.selectedProfileID == harness.profile.id)
            #expect(await harness.transport.controlRequests == [.armOnDemand(profileID: harness.profile.id, hasSecrets: false)])
            await harness.client.disconnect()
        }

        @Test
        func `a menu row of an armed profile selects it and leaves it armed`() async {
            let other = TunnelProfile(name: "Other")
            let harness = await makeHarness(.armedIdle)
            harness.model.profiles = [other, harness.profile]
            harness.model.selectedProfileID = other.id
            await harness.model.chooseFromMenu(harness.profile)
            #expect(harness.model.selectedProfileID == harness.profile.id)
            #expect(await harness.transport.controlRequests.isEmpty)
            await harness.client.disconnect()
        }

        @Test
        func `a menu row of a profile without a rule switches to it as before`() async {
            let backend = FakeTunnelBackend()
            let plain = TunnelProfile(name: "Plain")
            let model = MacShellModel(
                dependencies: .init(backend: backend, service: FakeServiceController(initial: .enabled), simulated: false),
                profiles: [plain],
            )
            model.daemonHooks.continuousNow = { XPCClock.continuousSeconds }
            model.receiveConnection(.connected(daemonBuild: 10))
            var idle = TunnelStatus.idle
            idle.measuredAt = Date()
            idle.measuredAtContinuous = XPCClock.continuousSeconds
            model.receive(idle, at: Date())
            await model.chooseFromMenu(plain)
            #expect(backend.calls.contains(.install(plain.id)))
            #expect(backend.calls.contains(.start(plain.id, transport: nil)))
        }
    }
#endif
