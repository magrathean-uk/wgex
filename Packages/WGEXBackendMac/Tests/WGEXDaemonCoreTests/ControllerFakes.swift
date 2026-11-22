// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

package enum HostTestError: Error { case injected }

package final class HostTrace: Sendable {
    private struct State: Sendable { var calls: [String] = []; var fail: String?; var repeating = false }
    private let state = Mutex(State())
    package var calls: [String] {
        state.withLock { $0.calls }
    }

    package func fail(at point: String?, repeating: Bool = false) {
        state.withLock { $0.fail = point; $0.repeating = repeating }
    }

    package func checkFault(_ point: String) throws {
        try state.withLock {
            if $0.fail == point {
                if !$0.repeating {
                    $0.fail = nil
                }; throw HostTestError.injected
            }
        }
    }

    package func record(_ point: String) throws {
        try state.withLock {
            $0.calls.append(point)
            if $0.fail == point {
                if !$0.repeating {
                    $0.fail = nil
                }; throw HostTestError.injected
            }
        }
    }
}

package actor HostEngine: EngineControlling {
    package nonisolated let events: AsyncStream<EngineEvent>
    package nonisolated let logs = AsyncStream<EngineLogLine> { $0.finish() }
    private let eventSink: AsyncStream<EngineEvent>.Continuation
    private let trace: HostTrace
    package private(set) var endpointLineCount = 0
    private var alive = false
    private let interfaceName: String
    package init(configuration _: EngineConfiguration) throws(EngineError) {
        trace = HostTrace(); interfaceName = "utun-test"; (events, eventSink) = AsyncStream.makeStream()
    }

    package init(trace: HostTrace, interfaceName: String = "utun-test") {
        self.trace = trace; self.interfaceName = interfaceName; (events, eventSink) = AsyncStream.makeStream()
    }

    package func setConfiguration(_ uapi: borrowing UAPIDocument) throws(EngineError) {
        guard uapi.byteCount > 0 else { throw .invalidHandle }
        endpointLineCount = uapi.bytes.withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self), prefix = Array("endpoint=".utf8)
            return bytes.indices.filter { offset in
                (offset == 0 || bytes[offset - 1] == 10) && offset + prefix.count <= bytes.count
                    && bytes[offset ..< offset + prefix.count].elementsEqual(prefix)
            }.count
        }
        try call("engine.configure")
    }

    package func up() throws(EngineError) {
        alive = true; try call("engine.up")
    }

    package func down() throws(EngineError) {
        alive = false; try call("engine.down")
    }

    package func updateEndpoints(_: [PublicKey: Endpoint]) throws(EngineError) {
        try call("engine.endpoints")
    }

    package func bumpSockets(v4 _: UInt32?, v6 _: UInt32?) throws(EngineError) {
        try call("engine.bump")
    }

    package func setTransport(_: TransportSpec) throws(EngineError) {
        try call("engine.transport")
    }

    package func forceHandshake() throws(EngineError) {
        try call("engine.handshake")
    }

    package func statistics() throws(EngineError) -> TunnelStatistics {
        guard alive else { throw .invalidHandle }
        return TunnelStatistics(
            generation: 0,
            sampledAt: Date(timeIntervalSince1970: 0),
            interfaceName: interfaceName,
            listenPort: nil,
            peers: [],
        )
    }

    package func shutdown() async {
        alive = false; try? trace.record("engine.shutdown"); eventSink.finish()
        try? await shutdownGate?.adapterCall(.createEngine, generation: .initial)
        shutdownReturns += 1
    }

    /// Parks `shutdown`, insensitively to cancellation, at this gate (keyed on `.createEngine`, which no other call of the
    /// engine uses). `shutdownReturns` counts shutdowns that have come back.
    private var shutdownGate: StepGate?
    package private(set) var shutdownReturns = 0
    package func parkShutdown(using gate: StepGate) {
        shutdownGate = gate
    }

    package func emit(_ event: EngineEvent) {
        eventSink.yield(event)
    }

    private func call(_ point: String) throws(EngineError) {
        do { try trace.record(point) } catch { throw .invalidHandle }
    }
}

package actor HostPorts: DaemonEngineCreating, DaemonRouteProgramming, DaemonDNSConfiguring, DaemonPolicyManaging,
    DaemonUnderlayResolving, TunnelDeviceConfiguring, ProtectionVerifying, DaemonRealityInspecting, InterfaceIdentityReading
{
    package let trace: HostTrace
    package var routeItems: [Generation: [RouteSpec]] = [:]
    package var dnsItems: [Generation: DNSConfiguration] = [:]
    package var identities: [Generation: TunnelIdentity] = [:]
    package var foreignRoutes: [RouteSpec] = []
    package var interfaceName = "utun-test"
    package func setInterfaceName(_ name: String) {
        interfaceName = name
    }

    /// The latest generation's identity under this name, as the kernel reader reports the created utun.
    package func identity(named name: String) -> TunnelIdentity? {
        identities.sorted { $0.key.rawValue > $1.key.rawValue }.first { $0.value.name == name }?.value
    }

    /// The addresses the fake device assigned to the interface.
    package func addresses(named name: String) -> [IPAddressRange] {
        deviceAddresses[name] ?? []
    }

    package var policy: PacketFilterPolicy = .disconnected
    private var verificationOverride: PFVerificationStatus?
    private var policyMeasured = true
    private var policyLoaded = true
    package private(set) var verificationReads = 0
    package func reportVerification(_ value: PFVerificationStatus) {
        verificationOverride = value
    }

    package var answers = ["192.0.2.1", "2001:db8::1"]
    package var modifiers: [PolicyModifiers] = []
    package var token: String?
    package var engine: HostEngine?
    package var injectedEngine: any EngineControlling?
    package func useEngine(_ engine: any EngineControlling) {
        injectedEngine = engine
    }

    package var configurations: [EngineConfiguration] = []
    package var deviceMTUs: [UInt16] = []
    /// Addresses the fake device assigned, by interface name.
    package var deviceAddresses: [String: [IPAddressRange]] = [:]
    private var suspension: StepGate?
    package func suspend(using gate: StepGate) {
        suspension = gate
    }

    /// Parks the device port inside `configure` and inside the post-configure identity read. Each has its own gate, and
    /// either gate is keyed on `.configureInterface` because neither call has a journal step of its own.
    private var configureGate: StepGate?
    private var confirmGate: StepGate?
    package func suspendConfigure(using gate: StepGate) {
        configureGate = gate
    }

    package func suspendConfirm(using gate: StepGate) {
        confirmGate = gate
    }

    /// The remaining off-actor adapters. Each gate is keyed on the step its call belongs to.
    private var verifyGate: StepGate?
    private var inspectGate: StepGate?
    private var removeOwnedGate: StepGate?
    private var removeAddressesGate: StepGate?
    package private(set) var removeOwnedCalls = 0
    package func suspendVerify(using gate: StepGate) {
        verifyGate = gate
    }

    package func suspendInspect(using gate: StepGate) {
        inspectGate = gate
    }

    package func suspendRemoveOwned(using gate: StepGate) {
        removeOwnedGate = gate
    }

    package func suspendRemoveAddresses(using gate: StepGate) {
        removeAddressesGate = gate
    }

    package init(trace: HostTrace) {
        self.trace = trace
    }

    package func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine {
        try trace.record("engine.create")
        let created = HostEngine(trace: trace, interfaceName: interfaceName)
        let identity = TunnelIdentity.held(interfaceName, index: 100, generation: generation)
        engine = created; configurations.append(configuration); identities[generation] = identity
        try await suspension?.adapterCall(.createEngine, generation: generation)
        return CreatedDaemonEngine(engine: injectedEngine ?? created, identity: identity)
    }

    package func canaryRoute(underlay: UnderlaySnapshot) throws -> OwnedCanaryRoute? {
        guard let router = underlay.ipv4Router, let name = underlay.interfaceV4Name, let index = underlay.v4 else { return nil }
        return try OwnedCanaryRoute(identity: TunnelIdentity(name: name, interfaceIndex: index), router: router)
    }

    package func install(_ routes: [RouteSpec], generation: Generation) async throws(DaemonFailure) {
        var current = routeItems[generation] ?? []
        for route in routes where !current.contains(route) {
            current.append(route)
        }
        routeItems[generation] = current; try call("routes.install")
        do { try await suspension?.adapterCall(.installRoutes, generation: generation) } catch { throw .portSystem(code: 5) }
    }

    package func removeCanaryRoute(of generation: Generation) async throws(DaemonFailure) {
        routeItems[generation]?.removeAll { $0.destination == "192.0.2.1" && $0.prefixLength == 32 }
        try call("routes.removeCanary")
    }

    package func removeRoutes(of generation: Generation) async throws(DaemonFailure) {
        routeItems.removeValue(forKey: generation); try call("routes.remove")
    }

    package func removeRoutes(_ routes: [RouteSpec], of generation: Generation) async throws(DaemonFailure) {
        routeItems[generation]?.removeAll { routes.contains($0) }; try call("routes.removeSome")
    }

    package func ownedRoutes() async -> [RouteSpec] {
        routeItems.values.flatMap(\.self)
    }

    package func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure) {
        dnsItems[generation] = configuration; try call("dns.apply")
        do { try await suspension?.adapterCall(.installDNS, generation: generation) } catch { throw .portSystem(code: 5) }
    }

    package func remove(generation: Generation) async throws(DaemonFailure) {
        dnsItems.removeValue(forKey: generation); try call("dns.remove")
    }

    package func current() async -> DNSConfiguration? {
        dnsItems.values.first
    }

    package func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        policyMeasured = false; policyLoaded = false
        let name: String = switch policy {
        case let .connecting(_, endpoints): endpoints.isEmpty ? "pf.blocking" : "pf.endpoints"
        case .connected: "pf.connected"
        case .disconnecting: "pf.disconnecting"
        case .disconnected: "pf.disconnected"
        case .error: "pf.error"
        case .lockdown: "pf.lockdown"
        case .captiveWindow: "pf.captive"
        }
        try call(name)
        try await suspendPolicy(policy)
        self.policy = policy; policyLoaded = true; policyMeasured = policy == .disconnected
    }

    private func suspendPolicy(_ policy: PacketFilterPolicy) async throws(DaemonFailure) {
        if case .error = policy {
            do { try await suspension?.adapterCall(.reconcileBlocking, generation: .initial) } catch { throw .portSystem(code: 5) }
        }
        if case .connected = policy {
            do { try await suspension?.adapterCall(.connected, generation: .initial) } catch { throw .portSystem(code: 5) }
        }
    }

    package func current() async -> PacketFilterPolicy {
        policy
    }

    package func verification() async -> PFVerificationStatus {
        verificationReads += 1
        if let verificationOverride {
            return verificationOverride
        }
        guard policyMeasured, policyLoaded else { return .unknown }
        return switch policy {
        case .error, .lockdown, .disconnecting, .connecting: .blocked
        case .connected: .protected
        case .captiveWindow: .captiveWindow
        case .disconnected: .unprotected
        }
    }

    package func setModifiers(_ modifiers: PolicyModifiers) async throws {
        self.modifiers.append(modifiers)
    }

    package var configuredProfiles: [TunnelProfile] = []
    package func configureProfile(_ profile: TunnelProfile) async {
        configuredProfiles.append(profile)
    }

    package private(set) var canaryChecks = 0
    package func verifyEvaluation() async throws {
        canaryChecks += 1
        guard policyLoaded else { throw DaemonFailure.pfVerification }
        do { try trace.checkFault("pf.canary"); policyMeasured = true }
        catch { policyMeasured = false; throw error }
    }

    package func acquireToken(existing: String?) async throws -> String {
        try trace.record("pf.acquire"); token = existing ?? token ?? "host-fake-token"; return token ?? "host-fake-token"
    }

    package func releaseToken(_: String) async throws {
        do { try trace.record("pf.release"); token = nil }
        catch { policyMeasured = false; throw error }
    }

    package func resolve(host _: String, interfaceIndex _: UInt32) async throws(DaemonFailure) -> [String] {
        try call("resolver.resolve")
        do { try await suspension?.adapterCall(.resolve, generation: .initial) } catch { throw .portSystem(code: 5) }
        return answers
    }

    package func configure(_ identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16, generation: Generation) async throws {
        deviceMTUs.append(mtu); deviceAddresses[identity.name] = addresses
        try trace.record("device.configure")
        try await configureGate?.adapterCall(.configureInterface, generation: generation)
    }

    package func identity(afterConfiguring identity: TunnelIdentity, engine _: any EngineControlling?) async throws -> TunnelIdentity {
        try trace.record("device.confirm")
        try await confirmGate?.adapterCall(.configureInterface, generation: .initial)
        return identity
    }

    package private(set) var removeAddressesReturned = 0
    package func removeAddresses(_: TunnelIdentity, generation: Generation) async throws {
        try trace.record("device.remove")
        try await removeAddressesGate?.adapterCall(.configureInterface, generation: generation)
        removeAddressesReturned += 1
    }

    package func verify(_ expectation: ProtectionExpectation) async throws {
        try trace.record("verify")
        try await verifyGate?.adapterCall(.verify, generation: expectation.resources.generation)
        guard routeItems[expectation.resources.generation] == expectation.resources.routes,
              dnsItems[expectation.resources.generation] == expectation.resources.dns,
              policy == expectation.policy else { throw HostTestError.injected }
        _ = try await expectation.engine.statistics()
    }

    package func inspect(_ resources: GenerationResources) async throws -> DaemonRealitySnapshot {
        try trace.record("reality.inspect")
        try await inspectGate?.adapterCall(.inspectReality, generation: resources.generation)
        let identity = identities[resources.generation]
        let routes = (routeItems[resources.generation] ?? []).compactMap { route -> ObservedDaemonRoute? in
            guard let identity else { return nil }
            return ObservedDaemonRoute(route: route, identity: identity, generation: resources.generation, hasProtocol2Flag: true)
        }
        return DaemonRealitySnapshot(identity: identity, routes: routes, dnsKey: resources.dnsKey, dns: dnsItems[resources.generation])
    }

    package func removeOwned(_ resources: GenerationResources) async throws {
        removeOwnedCalls += 1
        try await removeOwnedGate?.adapterCall(.inspectReality, generation: resources.generation)
        if let identity = resources.identity, identities[resources.generation] == identity {
            identities.removeValue(forKey: resources.generation)
        }
        if let current = routeItems[resources.generation] {
            let remaining = current.filter { !resources.routes.contains($0) }
            if remaining.isEmpty {
                routeItems.removeValue(forKey: resources.generation)
            } else {
                routeItems[resources.generation] = remaining
            }
        }
        if resources.dnsKey != nil, resources.dns == dnsItems[resources.generation] {
            dnsItems.removeValue(forKey: resources.generation)
        }
    }

    package func setForeign(_ routes: [RouteSpec]) {
        foreignRoutes = routes
    }

    package func setAnswers(_ values: [String]) {
        answers = values
    }

    private func call(_ point: String) throws(DaemonFailure) {
        do { try trace.record(point) } catch { throw .portSystem(code: 5) }
    }
}

/// One parked caller that `release()` resumes, and that cancellation resumes too unless `cancellable` is false.
///
/// A controller hook parks cancellably: a task cancelled while parked (a superseding operation cancels its predecessor)
/// unwinds, so a regression fails its test at an expectation or at the time limit instead of hanging the whole run
/// (M1-25 B6). A fake adapter parks insensitively, as the real adapters do: wgex_create and an ioctl ignore
/// cancellation, and the interleaving tests depend on a stale call returning after it was superseded.
package final class Parking: Sendable {
    private let waiter = Mutex<CheckedContinuation<Void, Never>?>(nil)
    package init() {}

    /// Parks until `release()` (or cancellation, when `cancellable`); `onParked` runs once the caller is registered.
    package func park(cancellable: Bool = true, onParked: @Sendable () -> Void) async {
        if cancellable {
            await withTaskCancellationHandler {
                await parkOnce(cancellable: true, onParked: onParked)
            } onCancel: {
                release()
            }
        } else {
            await parkOnce(cancellable: false, onParked: onParked)
        }
    }

    private func parkOnce(cancellable: Bool, onParked: @Sendable () -> Void) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let parkedNow = waiter.withLock { slot -> Bool in
                guard !(cancellable && Task.isCancelled) else { return false }
                slot = continuation
                return true
            }
            if parkedNow {
                onParked()
            } else {
                continuation.resume()
            }
        }
    }

    package func release() {
        waiter.withLock { slot -> CheckedContinuation<Void, Never>? in
            defer { slot = nil }
            return slot
        }?.resume()
    }
}

package actor StepGate: DaemonStepObserving {
    private let point: DaemonStep?
    private let failing: Bool
    private var enabled: Bool
    private var triggered = false
    private let parking = Parking()
    private let notifications: AsyncStream<Void>
    private let sink: AsyncStream<Void>.Continuation
    package init(point: DaemonStep? = nil, failing: Bool = false, enabled: Bool = true) {
        self.point = point; self.failing = failing; self.enabled = enabled; (notifications, sink) = AsyncStream.makeStream()
    }

    package func enable() {
        enabled = true
    }

    /// The controller's step hook. Parked cancellably: see `Parking`.
    package func before(_ step: DaemonStep, generation _: Generation) async throws {
        try await park(step, cancellable: true)
        try Task.checkCancellation()
    }

    /// A fake adapter call parked at this gate. Insensitive to cancellation, like the real adapter it stands in for.
    package func adapterCall(_ step: DaemonStep, generation _: Generation) async throws {
        try await park(step, cancellable: false)
    }

    private func park(_ step: DaemonStep, cancellable: Bool) async throws {
        guard enabled, step == point, !triggered else { return }
        triggered = true
        if failing {
            throw HostTestError.injected
        }
        let sink = sink
        await parking.park(cancellable: cancellable) { sink.yield(()) }
    }

    package func wait() async {
        for await _ in notifications {
            return
        }
    }

    package func release() {
        parking.release()
    }
}
