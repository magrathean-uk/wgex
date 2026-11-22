// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// A controller whose route, identity, device, DNS and verifier ports run on the XNU route model (M1-17), with the
/// model's RTM_ADD reachability rules and a pf evaluation canary sent through it (M1-19): en0 (index 4) carries
/// 192.0.2.10/24, so the underlay router 192.0.2.254 is on link.
package final class ModelStack: Sendable {
    /// What the device configure does to the utun besides assigning its addresses: nothing, move the stamp (the
    /// daemon's own SIOCSIFMTU), change the index, close the engine's descriptor, or lose the first assigned address.
    package enum Drift: Sendable { case none, sameIndex, newIndex(UInt32), descriptorClosed, addressGone }
    package let host: ControllerHarness
    package let model = DarwinRouteKernelModel()
    package let controller: TunnelController
    package let policy: ModelPolicy
    package var journal: DaemonJournal {
        host.journal
    }

    private let drift: Drift
    private let engineName: String

    package init(drift: Drift = .none, failingVerification: Int? = nil, engineName: String = "utun9") async throws {
        host = try ControllerHarness()
        try await host.install()
        await host.ports.setAnswers(["198.51.100.7"])
        model.attach("en0", index: 4)
        try model.assign([IPAddressRange("192.0.2.10/24")], to: "en0")
        model.enforceReachability()
        self.drift = drift; self.engineName = engineName
        policy = ModelPolicy(base: host.ports, model: model)
        controller = Self.controller(
            host: host, model: model, policy: policy, journal: host.journal, drift: drift, failing: failingVerification,
            engineName: engineName,
        )
    }

    /// The restarted daemon after a crash: same state directory, fresh journal, route table and controller.
    package func replacement() throws -> TunnelController {
        let journal = try DaemonJournal(directory: StateDirectory(root: host.root))
        return Self.controller(
            host: host, model: model, policy: policy, journal: journal, drift: drift, failing: nil, engineName: engineName,
        )
    }

    private static func controller(
        host: ControllerHarness, model: DarwinRouteKernelModel, policy: ModelPolicy, journal: DaemonJournal, drift: Drift,
        failing: Int?, engineName: String,
    ) -> TunnelController {
        let table = RouteTable(journal: journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 321)
        let dns = AcceptingDNS()
        let verifier = GatedVerifier(
            base: NetworkProtectionVerifier(routes: table, dns: dns, identities: model, policy: policy), failing: failing,
        )
        return TunnelController(
            registry: host.registry, secureInstall: VerifiedSecureInstall(), journal: journal, secrets: host.store,
            ports: .init(
                engineFactory: ModelEngineFactory(model: model, trace: host.trace, engineName: engineName), routes: table, dns: dns,
                policy: policy, resolver: host.ports, device: DriftingDevice(model: model, journal: journal, drift: drift),
                verifier: verifier, reality: NetworkRealityInspector(routes: table, dns: dns, identities: model),
            ),
            underlay: .init(
                v4: 4, v6: nil, resolvers: ["192.0.2.53"], interfaceNames: ["en0"], interfaceV4Name: "en0", ipv4Router: "192.0.2.254",
            ),
            clock: host.clock,
        )
    }

    package func start() async throws -> Generation {
        try await controller.start(profileID: host.profile.id, connectionUID: ControllerHarness.uid, secrets: ControllerHarness.bundle())
    }
}

/// The host policy fake whose evaluation canary is a datagram bound to en0 (index 4) and sent to 192.0.2.1 through the
/// route model. Like SystemCanaryProbe under PolicyEnforcer, a send without a route fails the evaluation with
/// pfCanaryFailed and leaves the loaded policy unmeasured (M1-19 D15).
package actor ModelPolicy: DaemonPolicyManaging {
    private let base: HostPorts
    private let model: DarwinRouteKernelModel
    private var failures = 0
    private var failuresAfterRouteFailure = 0
    /// The bound send's result for every evaluation: 0 or ENETUNREACH.
    package private(set) var probes: [Int32] = []
    package init(base: HostPorts, model: DarwinRouteKernelModel) {
        self.base = base; self.model = model
    }

    /// The next `count` evaluations fail as if the canary had no route, whatever the route model holds.
    package func failProbes(_ count: Int) {
        failures = count
    }

    package func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        try await base.apply(policy)
    }

    package func current() async -> PacketFilterPolicy {
        await base.current()
    }

    package func setModifiers(_ modifiers: PolicyModifiers) async throws {
        try await base.setModifiers(modifiers)
    }

    package func acquireToken(existing: String?) async throws -> String {
        try await base.acquireToken(existing: existing)
    }

    package func releaseToken(_ token: String) async throws {
        try await base.releaseToken(token)
    }

    package func verification() async -> PFVerificationStatus {
        await base.verification()
    }

    /// Once an RTM_ADD has failed, the next `count` evaluations fail as above.
    package func failProbesAfterRouteFailure(_ count: Int) {
        failuresAfterRouteFailure = count
    }

    package func verifyEvaluation() async throws {
        let code = try model.boundSend(to: "192.0.2.1", interfaceIndex: 4)
        probes.append(code)
        if failures > 0 {
            failures -= 1
            throw DaemonFailure(code: .pfCanaryFailed)
        }
        if failuresAfterRouteFailure > 0, model.failedAdds > 0 {
            failuresAfterRouteFailure -= 1
            throw DaemonFailure(code: .pfCanaryFailed)
        }
        guard code == 0 else { throw DaemonFailure(code: .pfCanaryFailed) }
        try await base.verifyEvaluation()
    }

    package func configureProfile(_ profile: TunnelProfile) async throws {
        await base.configureProfile(profile)
    }
}

/// Engine creation as the production factory reports it: the utun's name and index, and this process's descriptor for
/// it recorded for the generation (M1-18).
private struct ModelEngineFactory: DaemonEngineCreating {
    let model: DarwinRouteKernelModel
    let trace: HostTrace
    /// The name the engine reports; the kernel interface is always utun9.
    let engineName: String
    func create(configuration _: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
        CreatedDaemonEngine(
            engine: HostEngine(trace: trace, interfaceName: engineName), identity: model.attach("utun9", index: 9, generation: generation),
        )
    }
}

/// Configures like SystemTunnelDevice: identity-checked first, then the addresses, then SIOCSIFMTU, which moves
/// ifi_lastchange once the second has turned since creation. The post-configure confirmation is the production
/// SystemTunnelDevice implementation.
private actor DriftingDevice: TunnelDeviceConfiguring {
    private let model: DarwinRouteKernelModel
    private let system: SystemTunnelDevice
    private let journal: any DaemonJournalling
    private let drift: ModelStack.Drift
    init(model: DarwinRouteKernelModel, journal: any DaemonJournalling, drift: ModelStack.Drift) {
        self.model = model; self.drift = drift; self.journal = journal
        system = SystemTunnelDevice(identities: model, journal: journal)
    }

    func configure(_ identity: TunnelIdentity, addresses: [IPAddressRange], mtu _: UInt16, generation _: Generation) async throws {
        guard model.identity(named: identity.name) == identity else { throw DaemonFailure.portNotOwned }
        model.assign(addresses, to: identity.name)
        switch drift {
        case .none: break
        case .sameIndex: model.touch(identity.name)
        case let .newIndex(index): model.touch(identity.name, index: index)
        case .descriptorClosed: model.touch(identity.name); model.closeDescriptor(identity.name)
        case .addressGone: model.touch(identity.name); addresses.first.map { model.removeAddress($0, from: identity.name) }
        }
    }

    /// As SystemTunnelDevice: the journalled addresses, only while this process still holds the utun (M1-19).
    func removeAddresses(_ identity: TunnelIdentity, generation: Generation) async throws {
        guard try await model.admits(identity, fence: .tunnel(addresses: [])),
              let resource = journal.snapshot().resources.first(where: { $0.generation == generation && $0.identity == identity })
        else { return }
        for address in resource.addresses {
            model.removeAddress(address, from: identity.name)
        }
    }

    func identity(afterConfiguring identity: TunnelIdentity) async throws -> TunnelIdentity {
        try await system.identity(afterConfiguring: identity)
    }

    func identity(afterConfiguring identity: TunnelIdentity, engine: any EngineControlling?) async throws -> TunnelIdentity {
        try await system.identity(afterConfiguring: identity, engine: engine)
    }
}

/// Fails exactly one verification, by call number; the second call follows the connected policy as in guest run 6.
private actor GatedVerifier: ProtectionVerifying {
    private let base: NetworkProtectionVerifier
    private let failing: Int?
    private var calls = 0
    init(base: NetworkProtectionVerifier, failing: Int?) {
        self.base = base; self.failing = failing
    }

    func verify(_ expectation: ProtectionExpectation) async throws {
        calls += 1
        if calls == failing {
            throw DaemonFailure.portNotOwned
        }
        try await base.verify(expectation)
    }
}

/// Publishes and verifies the synthetic resolver in memory.
package actor AcceptingDNS: DaemonDNSConfiguring {
    private var published: [Generation: DNSConfiguration] = [:]
    package init() {}
    package func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure) {
        published[generation] = configuration
    }

    package func remove(generation: Generation) async throws(DaemonFailure) {
        published.removeValue(forKey: generation)
    }

    package func current() async -> DNSConfiguration? {
        published.values.first
    }

    package func verify(_ resources: GenerationResources) async throws {
        guard resources.dns == nil || published[resources.generation] == resources.dns else { throw DaemonFailure.portNotOwned }
    }
}

/// An engine whose statistics carry no interface name; the Go engine never does this (its name is fixed at construction).
package actor NamelessEngine: EngineControlling {
    package nonisolated let events = AsyncStream<EngineEvent> { $0.finish() }
    package nonisolated let logs = AsyncStream<EngineLogLine> { $0.finish() }
    package init() {}
    package init(configuration _: EngineConfiguration) throws(EngineError) {}
    package func setConfiguration(_: borrowing UAPIDocument) throws(EngineError) {}
    package func updateEndpoints(_: [PublicKey: Endpoint]) throws(EngineError) {}
    package func up() throws(EngineError) {}
    package func down() throws(EngineError) {}
    package func bumpSockets(v4 _: UInt32?, v6 _: UInt32?) throws(EngineError) {}
    package func setTransport(_: TransportSpec) throws(EngineError) {}
    package func forceHandshake() throws(EngineError) {}
    package func statistics() throws(EngineError) -> TunnelStatistics {
        TunnelStatistics(generation: 0, sampledAt: Date(timeIntervalSince1970: 0), interfaceName: nil, listenPort: nil, peers: [])
    }

    package func shutdown() async {}
}
