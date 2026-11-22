// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// Opens once; a command suspended on it models a control command waiting on the daemon.
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var isOpen = false

        func wait() async {
            guard !isOpen else { return }
            await withCheckedContinuation { continuation = $0 }
        }

        func open() {
            isOpen = true
            continuation?.resume()
            continuation = nil
        }
    }

    @MainActor
    private final class OnDemandCalls {
        var armed: [UUID] = []
        var disarmed: [UUID] = []
    }

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacOnDemandShellTests {
        /// A bounded wait: a condition that never holds fails the test instead of hanging it.
        private func until(_ condition: () -> Bool) async -> Bool {
            for _ in 0 ..< 5000 {
                if condition() {
                    return true
                }
                await Task.yield()
            }
            return condition()
        }

        private static let rule = OnDemandPolicy.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"])))

        private func profile(_ name: String = "Home VPN", policy: OnDemandPolicy = rule) -> TunnelProfile {
            var profile = TunnelProfile(name: name)
            profile.onDemand = policy
            return profile
        }

        private func shell(
            profiles: [TunnelProfile], calls: OnDemandCalls = OnDemandCalls(), gate: Gate? = nil,
            backend: FakeTunnelBackend = FakeTunnelBackend(), simulated: Bool = false, hostGuarded: Bool = false,
            arm: ((TunnelProfile) async throws -> Void)? = nil,
        ) -> MacShellModel {
            let operations = MacShellOperations(
                errorCopy: MacAppErrorCopy.resolve,
                armOnDemand: arm ?? { profile in
                    await gate?.wait()
                    calls.armed.append(profile.id)
                },
                disarmOnDemand: { id in
                    await gate?.wait()
                    calls.disarmed.append(id)
                },
            )
            let model = MacShellModel(
                dependencies: .init(
                    backend: backend, service: FakeServiceController(initial: .enabled), simulated: simulated,
                    hostGuarded: hostGuarded, operations: operations,
                ),
                profiles: profiles,
            )
            model.receiveConnection(.connected(daemonBuild: 10))
            return model
        }

        private func status(
            armed: UUID? = nil, activated: Bool = false, active: UUID? = nil, ssid: OnDemandStatus.SSIDState = .notRequired,
            decision: OnDemandStatus.Decision? = nil, phase: TunnelPhase? = nil,
        ) -> TunnelStatus {
            var status = TunnelStatus.idle
            status.activeProfileID = active
            if let phase {
                status.phase = phase
            } else if active != nil {
                status.phase = .active(Generation(rawValue: 1))
            }
            if armed != nil || activated {
                status.onDemand = OnDemandStatus(
                    armedProfileID: armed, activated: activated, network: .wifi, ssid: ssid, decision: decision,
                )
            }
            return status
        }

        // MARK: Presentation

        @Test
        func `the window and menu say whether on-demand is armed and whether it brought the tunnel up`() {
            let profile = profile()
            let model = shell(profiles: [profile])
            var presentation = model.onDemandPresentation(for: profile)
            #expect(presentation?.title == MacStrings.onDemandNotArmed)
            #expect(presentation?.isArmed == false)
            model.receive(status(armed: profile.id, decision: .connect), at: Date())
            presentation = model.onDemandPresentation(for: profile)
            #expect(presentation?.title == MacStrings.onDemandArmed)
            #expect(presentation?.activated == false)
            #expect(presentation?.detail == MacStrings.onDemandDecisionConnect)
            model.receive(status(armed: profile.id, activated: true, active: profile.id, decision: .connect), at: Date())
            presentation = model.onDemandPresentation(for: profile)
            #expect(presentation?.title == MacStrings.onDemandArmedActivated)
            #expect(presentation?.activated == true)
        }

        @Test
        func `a profile with no rule has no on-demand surface unless it is armed`() {
            let plain = profile("Plain", policy: .off)
            let model = shell(profiles: [plain])
            #expect(model.onDemandPresentation(for: plain) == nil)
            #expect(!model.isOnDemandConfigured(plain))
            #expect(!model.isOnDemandConfigured(profile("Cell", policy: .cellularOnly)))
            #expect(model.isOnDemandConfigured(profile("Legacy", policy: .always(exceptSSIDs: []))))
        }

        @Test(arguments: [
            (OnDemandStatus.Decision.disconnect, OnDemandStatus.SSIDState.notRequired, MacStrings.onDemandDecisionDisconnect),
            (.hold(.noNetwork), .notRequired, MacStrings.onDemandHoldNoNetwork),
            (.hold(.ssidUnavailable), .unavailable(.noReporter), MacStrings.onDemandNameNoReporter),
            (.hold(.ssidUnavailable), .unavailable(.notAuthorised), MacStrings.onDemandNameNotAuthorised),
            (.hold(.ssidUnavailable), .unavailable(.timedOut), MacStrings.onDemandNameTimedOut),
            (.hold(.ssidUnavailable), .unavailable(.unreadable), MacStrings.onDemandNameUnreadable),
            (.connect, .settling, MacStrings.onDemandSettling),
            (.paused(.ownerNotConsoleUser), .notRequired, MacStrings.onDemandPausedOwner),
            (.paused(.recovering), .notRequired, MacStrings.onDemandPausedRecovering),
            (.paused(.cutoverArmed), .notRequired, MacStrings.onDemandPausedCutover),
        ])
        func `the daemon's reason is shown without any network name`(
            _ decision: OnDemandStatus.Decision, _ ssid: OnDemandStatus.SSIDState, _ expected: String,
        ) {
            let profile = profile()
            let model = shell(profiles: [profile])
            model.receive(status(armed: profile.id, ssid: ssid, decision: decision), at: Date())
            #expect(model.onDemandPresentation(for: profile)?.detail == expected)
        }

        @Test
        func `before the first evaluation the card says it is waiting`() {
            let profile = profile()
            let model = shell(profiles: [profile])
            model.receive(status(armed: profile.id), at: Date())
            #expect(model.onDemandPresentation(for: profile)?.detail == MacStrings.onDemandNoEvaluation)
        }

        // MARK: Arming through the shell

        @Test
        func `arming installs the current profile then arms and disarming stops through the daemon`() async {
            let profile = profile()
            let calls = OnDemandCalls()
            let backend = FakeTunnelBackend()
            let model = shell(profiles: [profile], calls: calls, backend: backend)
            await model.setOnDemand(true, for: profile)
            #expect(backend.calls.contains(.install(profile.id)))
            #expect(calls.armed == [profile.id])
            #expect(model.pendingAction == nil)
            await model.setOnDemand(false, for: profile)
            #expect(calls.disarmed == [profile.id])
        }

        @Test
        func `a profile without a rule is never sent for arming`() async {
            let plain = profile("Plain", policy: .off)
            let calls = OnDemandCalls()
            let model = shell(profiles: [plain], calls: calls)
            await model.setOnDemand(true, for: plain)
            #expect(calls.armed.isEmpty)
        }

        @Test(arguments: [(true, false, false), (false, true, false), (false, false, true)])
        func `previews, the host guard and a missing service never arm`(_ simulated: Bool, _ guarded: Bool, _ stopped: Bool) async {
            let profile = profile()
            let calls = OnDemandCalls()
            let model = shell(profiles: [profile], calls: calls, simulated: simulated, hostGuarded: guarded)
            if stopped {
                model.receiveConnection(.disconnected(lastError: nil))
            }
            #expect(!model.canChangeOnDemand)
            await model.setOnDemand(true, for: profile)
            #expect(calls.armed.isEmpty)
        }

        @Test
        func `a refused arm reports the fixed on-demand copy`() async {
            let profile = profile()
            let model = shell(profiles: [profile], arm: { _ in
                try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { throw DaemonError.onDemandNotConfigured }
            })
            await model.setOnDemand(true, for: profile)
            #expect(model.operationMessage == MacErrorCopy(.onDemandNotConfigured).message)
            #expect(model.pendingAction == nil)
        }

        @Test
        func `a slow stop holding the lane shows the pending command instead of a hung window`() async {
            let profile = profile()
            let gate = Gate()
            let model = shell(profiles: [profile], gate: gate)
            let running = Task { await model.setOnDemand(true, for: profile) }
            #expect(await until { model.pendingAction != nil })
            #expect(model.pendingAction == .arming(profile.id))
            #expect(model.pendingActionText == MacStrings.pendingArming + "… " + MacStrings.pendingWorking)
            #expect(!model.canChangeOnDemand)
            model.receive(
                status(active: profile.id, phase: .stopping(Generation(rawValue: 1), reason: .userRequested)), at: Date(),
            )
            #expect(model.pendingActionText == MacStrings.pendingArming + "… " + MacStrings.pendingWaitingForStop)
            await gate.open()
            await running.value
            #expect(model.pendingAction == nil)
            #expect(model.pendingActionText == nil)
        }

        @Test
        func `a start sent behind a slow stop shows progress on the row and the window until the stop ends`() async {
            let running = profile(policy: .off)
            let target = profile("Work VPN", policy: .off)
            let gate = Gate()
            let model = shell(profiles: [running, target])
            model.selectedProfileID = target.id
            model.receive(status(active: running.id), at: Date())
            model.daemonHooks.stopCurrent = {
                await gate.wait()
            }
            #expect(model.inactiveRowState(target) == MacStrings.inactive)
            let starting = Task { await model.toggleConnection() }
            #expect(await until { model.pendingAction != nil })
            #expect(model.pendingAction == .connecting(target.id))
            model.receive(
                status(active: running.id, phase: .stopping(Generation(rawValue: 1), reason: .userRequested)), at: Date(),
            )
            #expect(model.isStarting(target))
            #expect(!model.isStarting(running))
            #expect(model.inactiveRowState(target) == MacStrings.pendingConnecting + "… " + MacStrings.pendingWaitingForStopShort)
            #expect(model.pendingActionText == MacStrings.pendingConnecting + "… " + MacStrings.pendingWaitingForStop)
            #expect(model.connectionRequestInFlight)
            await gate.open()
            await starting.value
            #expect(model.pendingAction == nil)
            #expect(model.pendingActionText == nil)
            #expect(model.inactiveRowState(target) == MacStrings.inactive)
            #expect(!model.connectionRequestInFlight)
        }

        @Test
        func `disconnecting names itself while the stop is in flight`() async {
            let profile = profile(policy: .off)
            let gate = Gate()
            let model = shell(profiles: [profile])
            model.daemonHooks.stopCurrent = { await gate.wait() }
            model.receive(status(active: profile.id), at: Date())
            // A command in flight turns the primary action into cancel, which is the disconnect path.
            model.connectionRequestInFlight = true
            let running = Task { await model.toggleConnection() }
            #expect(await until { model.pendingAction != nil })
            #expect(model.pendingAction == .disconnecting)
            #expect(model.pendingActionText == MacStrings.pendingDisconnecting + "… " + MacStrings.pendingWorking)
            await gate.open()
            await running.value
            model.connectionRequestInFlight = false
            #expect(model.pendingAction == nil)
        }
    }

    private extension MacOnDemandShellTests {
        // MARK: Activation provenance and unavailable network names

        @Test
        func `activation belongs to the profile the daemon is running, not to the armed one`() {
            let armed = profile("Armed")
            let other = profile("Other")
            let model = shell(profiles: [armed, other])
            model.receive(status(armed: armed.id, activated: true, active: other.id, decision: .hold(.anotherTunnelActive)), at: Date())
            #expect(model.onDemandPresentation(for: armed)?.activated == false)
            #expect(model.onDemandPresentation(for: armed)?.detail == MacStrings.onDemandHoldAnotherTunnel)
            #expect(model.onDemandPresentation(for: other)?.isArmed == false)
            #expect(model.onDemandPresentation(for: other)?.activated == true)
            #expect(model.isBroughtUpByOnDemand(other.id) && !model.isBroughtUpByOnDemand(armed.id))
        }

        /// Saving the policy as Off disarms the profile and leaves the tunnel up; the daemon keeps reporting `activated`.
        @Test(arguments: [OnDemandPolicy.off, OnDemandPolicy.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"])))])
        func `a tunnel on-demand brought up stays shown after the profile is disarmed`(_ policy: OnDemandPolicy) {
            let profile = profile(policy: policy)
            let model = shell(profiles: [profile])
            model.receive(status(armed: profile.id, activated: true, active: profile.id, decision: .connect), at: Date())
            #expect(model.onDemandPresentation(for: profile)?.title == MacStrings.onDemandArmedActivated)
            model.receive(status(activated: true, active: profile.id), at: Date())
            #expect(!model.isOnDemandArmed(profile.id))
            let presentation = model.onDemandPresentation(for: profile)
            #expect(presentation?.title == MacStrings.onDemandNotArmedActivated)
            #expect(presentation?.detail == MacStrings.onDemandStayedUp)
            #expect(presentation?.isArmed == false)
            #expect(presentation?.activated == true)
        }

        @Test
        func `a disarmed on-demand tunnel only shows, it cannot be armed without a rule`() async {
            let profile = profile(policy: .off)
            let calls = OnDemandCalls()
            let model = shell(profiles: [profile], calls: calls)
            model.receive(status(activated: true, active: profile.id), at: Date())
            #expect(model.canChangeOnDemand)
            #expect(!model.canToggleOnDemand(profile))
            await model.setOnDemand(true, for: profile)
            #expect(calls.armed.isEmpty)
        }

        @Test
        func `the activation note goes when the tunnel goes or belongs to another profile`() {
            let profile = profile(policy: .off)
            let other = self.profile("Other", policy: .off)
            let model = shell(profiles: [profile, other])
            model.receive(status(activated: true, active: profile.id), at: Date())
            #expect(model.onDemandPresentation(for: other) == nil)
            model.receive(status(), at: Date())
            #expect(model.onDemandPresentation(for: profile) == nil)
            // A manual tunnel carries no on-demand status at all.
            model.receive(status(active: profile.id), at: Date())
            #expect(model.onDemandPresentation(for: profile) == nil)
            #expect(!model.isBroughtUpByOnDemand(profile.id))
        }

        /// An excluded list skips its disconnect rule, so the outcome is connect (ADR-030 section 4); the reason, the consequence
        /// and the recovery come with it, whatever profile policy is armed.
        @Test(arguments: [
            (OnDemandStatus.SSIDUnavailableReason.noReporter, MacStrings.onDemandConnectNameNoReporter, "Open WGEX"),
            (.notAuthorised, MacStrings.onDemandConnectNameNotAuthorised, "Allow Location"),
            (.timedOut, MacStrings.onDemandConnectNameTimedOut, "keep WGEX open"),
            (.unreadable, MacStrings.onDemandConnectNameUnreadable, "Location is allowed"),
        ])
        func `an excluded list that connects because the network name is unavailable says why and what to do`(
            _ reason: OnDemandStatus.SSIDUnavailableReason, _ expected: String, _ guidance: String,
        ) {
            let profile = profile(policy: .interfaces(.wifiOnly(.exceptSSIDs(["Home"]))))
            let model = shell(profiles: [profile])
            model.receive(status(armed: profile.id, ssid: .unavailable(reason), decision: .connect), at: Date())
            let detail = model.onDemandPresentation(for: profile)?.detail
            #expect(detail == expected)
            #expect(detail != MacStrings.onDemandDecisionConnect)
            #expect(detail?.hasPrefix(String(MacStrings.onDemandDecisionConnect.dropLast()) + " because") == true)
            #expect(detail?.localizedCaseInsensitiveContains(guidance) == true)
            #expect(detail?.contains("Home") == false)
            // The same connect outcome with the name readable keeps the short caption.
            model.receive(status(armed: profile.id, ssid: .known, decision: .connect), at: Date())
            #expect(model.onDemandPresentation(for: profile)?.detail == MacStrings.onDemandDecisionConnect)
        }
    }

    private extension MacOnDemandShellTests {
        // MARK: Saving from the editor (ADR-030 section 6 rule 7)

        private func app(
            shell: MacShellModel, root: URL, secrets: InMemorySecretStore, persistence: MacPersistence,
        ) -> MacAppModel {
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets)
            return MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
        }

        @Test(arguments: [(true, false, true), (true, true, false), (false, false, false)])
        func `saving a rule onto a tunnel that is up arms it once and only then`(
            _ active: Bool, _ alreadyHadRule: Bool, _ expectsArm: Bool,
        ) async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let persistence = MacPersistence(container: root, simulated: true)
            let secrets = InMemorySecretStore()
            let calls = OnDemandCalls()
            let model = shell(profiles: [], calls: calls)
            let app = app(shell: model, root: root, secrets: secrets, persistence: persistence)
            var parsed = try EditorFixtures.parsed()
            parsed.profile.onDemand = alreadyHadRule ? Self.rule : .off
            let original = try await app.repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            model.profiles = [original]
            model.receive(status(active: active ? original.id : nil), at: Date())
            let editor = try ProfileEditorModel(profile: original, secrets: parsed.secrets)
            editor.draft.onDemandForm = MacOnDemandForm(policy: .interfaces(.ethernetOnly))
            try await editor.save(using: app.saveEditor)
            #expect(calls.armed == (expectsArm ? [original.id] : []))
            #expect(model.profiles.first?.onDemand == .interfaces(.ethernetOnly))
        }

        // MARK: Daemon round trip with a fake client

        @Test
        func `arming, disarming and the refusal travel as the ADR messages through the client`() async {
            let profile = profile()
            let transport = OnDemandTransport()
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
            model.receiveConnection(.connected(daemonBuild: 10))
            await model.setOnDemand(true, for: profile)
            await model.setOnDemand(false, for: profile)
            let requests = await transport.requests
            #expect(requests.contains(.armOnDemand(profileID: profile.id, hasSecrets: false)))
            #expect(requests.contains(.disarmOnDemand(profileID: profile.id)))
            #expect(model.operationMessage == nil)
            await transport.refuseArming()
            await model.setOnDemand(true, for: profile)
            #expect(model.operationMessage == MacErrorCopy(.onDemandNotConfigured).message)
            await client.disconnect()
        }
    }

    /// Answers the handshake and the on-demand requests; records everything the client sends.
    private actor OnDemandTransport: XPCTransport {
        private(set) var requests: [Request] = []
        private var refuse = false

        func refuseArming() {
            refuse = true
        }

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
            case .armOnDemand where refuse: return try WireCodec.encode(Reply.error(.onDemandNotConfigured))
            default: return try WireCodec.encode(Reply.ok)
            }
        }
    }
#endif
