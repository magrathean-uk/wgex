// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonCore
    import WGEXDaemonProtocol
    import WGEXEngineInterface
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    package final nonisolated class ControllerShellClock: DaemonClock {
        private let elapsed = Mutex<TimeInterval>(0)
        package var now: Duration {
            .seconds(elapsed.withLock { $0 })
        }

        package var wallNow: Date {
            Date(timeIntervalSince1970: 1000 + elapsed.withLock { $0 })
        }

        package var continuousNow: TimeInterval {
            100 + elapsed.withLock { $0 }
        }

        package func advance(_ seconds: TimeInterval) {
            elapsed.withLock { $0 += seconds }
        }

        package func sleep(for duration: Duration) async throws {
            try await ContinuousClock().sleep(for: duration)
        }
    }

    /// Only the controller/client are real; every resource adapter is an in-memory fake.
    @MainActor package final class ControllerShellFixture {
        package let root: URL
        package let clock = ControllerShellClock()
        package let controller: TunnelController
        package let composition: DaemonComposition
        package let client: DaemonClient
        package let profile: TunnelProfile
        package let registry: ProfileRegistry
        package let journal: DaemonJournal
        package let shell: MacShellModel

        package init(steps: any DaemonStepObserving = UninterruptedDaemonSteps()) throws {
            root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-shell-" + UUID().uuidString)
            let directory = try StateDirectory(root: root)
            journal = try DaemonJournal(directory: directory)
            let secrets = ControllerShellSecrets()
            registry = try ProfileRegistry(
                repository: DirectoryProfileRepository(directory: directory),
                secrets: InMemorySecretStore(), bundles: secrets,
            )
            let ports = ControllerShellPorts()
            controller = TunnelController(
                registry: registry, secureInstall: ControllerShellInstall(), journal: journal, secrets: secrets,
                ports: .init(
                    engineFactory: ports,
                    routes: FakeRouteTable(),
                    dns: FakeDNSConfigurator(),
                    policy: ports,
                    resolver: ports,
                    device: ports,
                    verifier: ports,
                    reality: ports,
                ),
                underlay: .init(v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["fixture"]), clock: clock, steps: steps,
            )
            let sequence = Mutex<UInt64>(0)
            composition = DaemonComposition(
                controller: controller,
                daemonVersion: "1",
                daemonBuild: 10,
                minimumClientBuild: 1,
                authorisation: .init(isConsoleUser: { _ in true }),
                nextStatusSequence: { sequence.withLock { $0 += 1; return $0 } },
            )
            client = Self.makeClient(dispatcher: composition.dispatcher, clock: clock)
            profile = try Self.makeProfile()
            shell = MacShellModel(dependencies: .init(
                backend: client,
                service: FakeServiceController(initial: .enabled),
                simulated: false,
            ), profiles: [profile])
            shell.daemonHooks.continuousNow = { [clock] in clock.continuousNow }
            shell.daemonHooks.stopCurrent = { [client] in try await client.stopCurrent() }
        }

        package func start() async throws {
            _ = try await registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
            let writer = try SecretsWireWriter(privateKey: Self.key("client1.key"))
            _ = try await controller.start(
                profileID: profile.id,
                connectionUID: 501,
                secrets: SecretsWireLayout.decode(writer.finish()),
            )
        }

        package func refresh() async throws {
            _ = try await client.connect()
            try await client.refreshStatus()
            var updates = client.statusUpdates().makeAsyncIterator()
            let status = try #require(await updates.next())
            shell.receive(status, at: clock.wallNow)
            shell.receiveConnection(.connected(daemonBuild: 10))
        }

        package func close() async {
            await client.disconnect()
            await composition.dispatcher.stopHeartbeat()
            try? FileManager.default.removeItem(at: root)
        }

        private static func makeClient(dispatcher: DaemonDispatcher, clock: ControllerShellClock) -> DaemonClient {
            DaemonClient(
                transport: InMemoryXPCTransport(
                    daemon: dispatcher,
                    peer: .init(
                        uid: 501,
                        pid: 7,
                        auditSessionID: 1,
                        codeSigningVerdict: .requirementSatisfied,
                    ),
                ),
                clientVersion: "1",
                clientBuild: 10,
                clock: .init(
                    now: { [clock] in clock.continuousNow },
                    sleep: { try await ContinuousClock().sleep(for: $0) },
                ),
            )
        }

        private static func makeProfile() throws -> TunnelProfile {
            var profile = TunnelProfile(name: "Real controller fixture")
            profile.interface = try InterfaceConfiguration(
                addresses: [IPAddressRange("10.77.0.2/32")],
                dns: [DNSServer("10.77.0.1")],
                publicKey: PrivateKey(bytes: Self.key("client1.key")).publicKey(),
            )
            profile.peers = try [PeerConfiguration(
                publicKey: PrivateKey(bytes: Self.key("client2.key")).publicKey(),
                allowedIPs: [IPAddressRange("0.0.0.0/0")],
                endpoint: Endpoint("192.0.2.1:51820"),
            )]
            profile.protection.ipv6Policy = .blockOutside
            return profile
        }

        private nonisolated static func key(_ name: String) throws -> SecretBytes {
            var data = try FixtureLoader.repository().data("keys/" + name)
            let input = try SecretBytes(wiping: &data)
            let range = try #require(input.withUnsafeBytes { raw -> Range<Int>? in
                var start = 0
                for end in raw.indices where raw[end] == 10 {
                    if start < end, raw[start] != 35 {
                        return start ..< (raw[end - 1] == 13 ? end - 1 : end)
                    }
                    start = end + 1
                }
                return nil
            })
            let key = try PrivateKey(parsing: SecretBytes(copying: input, range: range), encoding: .base64)
            var result = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &result)
            return result
        }
    }

    package actor ControllerShellStartGate: DaemonStepObserving {
        private var parked: CheckedContinuation<Void, Never>?
        private let ready = AsyncStream<Void>.makeStream()
        package func before(_ step: DaemonStep, generation _: Generation) async {
            guard step == .createEngine else { return }
            await withCheckedContinuation { parked = $0; ready.continuation.yield(()) }
        }

        package func wait() async {
            for await _ in ready.stream {
                return
            }
        }

        package func release() {
            parked?.resume(); parked = nil
        }
    }

    private nonisolated struct ControllerShellSecrets: TunnelSecretStoring {
        func saveBundle(_: consuming SecretBytes, profileID _: UUID) {}
        func loadBundle(profileID _: UUID) throws -> SecretBytes {
            throw TunnelError.secretsUnavailable
        }

        func deleteBundle(profileID _: UUID) {}
    }

    private nonisolated struct ControllerShellInstall: SecureInstallChecking {
        func status() -> SecureInstallReport {
            .init(state: .verified, bundlePath: "/Applications/WGEX.app", isUnderApplications: true)
        }

        func perform() -> SecureInstallReport {
            status()
        }
    }

    private actor ControllerShellPorts: DaemonEngineCreating, DaemonPolicyManaging, UnderlayResolving,
        TunnelDeviceConfiguring, ProtectionVerifying, DaemonRealityInspecting
    {
        var policy: PacketFilterPolicy = .disconnected
        func create(configuration: EngineConfiguration, generation _: Generation) throws -> CreatedDaemonEngine {
            try .init(
                engine: FakeEngine(configuration: configuration),
                identity: .init(name: "utun-fixture", interfaceIndex: 100, creationID: UUID()),
            )
        }

        func current() -> PacketFilterPolicy {
            policy
        }

        func apply(_ policy: PacketFilterPolicy) {
            self.policy = policy
        }

        func setModifiers(_: PolicyModifiers) {}
        func configureProfile(_: TunnelProfile) {}
        func acquireToken(existing: String?) -> String {
            existing ?? "fixture-token"
        }

        func releaseToken(_: String) {}
        func killStates(on _: [String]) {}
        func verifyEvaluation() {}
        func verification() -> PFVerificationStatus {
            switch policy {
            case .connected: .protected
            case .disconnected: .unprotected
            case .captiveWindow: .captiveWindow
            default: .blocked
            }
        }

        func resolve(host _: String, interfaceIndex _: UInt32) -> [String] {
            ["192.0.2.1"]
        }

        func configure(_: TunnelIdentity, addresses _: [IPAddressRange], mtu _: UInt16, generation _: Generation) {}
        func removeAddresses(_: TunnelIdentity, generation _: Generation) {}
        func verify(_ expectation: ProtectionExpectation) async throws {
            _ = try await expectation.engine.statistics()
        }

        func inspect(_: GenerationResources) -> DaemonRealitySnapshot {
            .init(identity: nil, routes: [], dnsKey: nil, dns: nil)
        }

        func removeOwned(_: GenerationResources) {}
    }
#endif
