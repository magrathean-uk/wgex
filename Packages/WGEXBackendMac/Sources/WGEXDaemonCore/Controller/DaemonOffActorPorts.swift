// SPDX-License-Identifier: MIT
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface

/// The adapter calls that run off the controller actor. Each can hold a pool thread for as long as the host is slow,
/// and an abandoned call (the watchdog expired, or a newer operation superseded it) may never return.
package enum OffActorCall: Sendable, CaseIterable {
    case createEngine, configure, confirm, verify, inspect, removeOwned, removeAddresses
}

/// Blocking host adapters run here, never on the controller actor.
///
/// `NonisolatedNonsendingByDefault` makes a `nonisolated async` adapter run on its caller's executor, so a syscall, ioctl
/// or cgo call inside one occupies the controller actor: status replies, the watchdog's own expiry and every other
/// controller job wait behind it (M1-24 section 1.3). A `@concurrent` function leaves the actor for the global executor,
/// and the adapter it calls runs there. The caller resumes on the actor and must re-check its generation before it
/// continues, because stop, a settings change or a newer start can be admitted while it was away; every call site does.
///
/// The cooperative pool is as wide as the core count, so a call that never returns must not be issued again while it is
/// outstanding: `TunnelController.offActor(_:_:)` admits at most one call per kind and refuses the next one closed.
package enum OffActor {
    @concurrent
    package static func createEngine(
        _ factory: any DaemonEngineCreating, configuration: EngineConfiguration, generation: Generation,
    ) async throws -> CreatedDaemonEngine {
        try await factory.create(configuration: configuration, generation: generation)
    }

    @concurrent
    package static func configure(
        _ device: any TunnelDeviceConfiguring, identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16,
        generation: Generation,
    ) async throws {
        try await device.configure(identity, addresses: addresses, mtu: mtu, generation: generation)
    }

    @concurrent
    package static func confirm(
        _ device: any TunnelDeviceConfiguring, identity: TunnelIdentity, engine: any EngineControlling?,
    ) async throws -> TunnelIdentity {
        try await device.identity(afterConfiguring: identity, engine: engine)
    }

    @concurrent
    package static func verify(_ verifier: any ProtectionVerifying, _ expectation: ProtectionExpectation) async throws {
        try await verifier.verify(expectation)
    }

    @concurrent
    package static func inspect(
        _ reality: any DaemonRealityInspecting, _ resources: GenerationResources,
    ) async throws -> DaemonRealitySnapshot {
        try await reality.inspect(resources)
    }

    @concurrent
    package static func removeOwned(_ reality: any DaemonRealityInspecting, _ resources: GenerationResources) async throws {
        try await reality.removeOwned(resources)
    }

    @concurrent
    package static func removeAddresses(
        _ device: any TunnelDeviceConfiguring, identity: TunnelIdentity, generation: Generation,
    ) async throws {
        try await device.removeAddresses(identity, generation: generation)
    }
}

package extension TunnelController {
    /// Admits one outstanding off-actor call per kind. A call whose operation was abandoned may never return; issuing the
    /// next attempt's call while it is outstanding would park another pool thread on every expiry cycle. The refused
    /// attempt fails closed (the blocking policy stays loaded) and the retry schedule tries again once the old call has
    /// returned. The marker clears on the actor when the call returns, however late. A refusal says so once, in fixed words
    /// (the kind is a case name, nothing else), so a guest run can tell it from a real failure of the adapter.
    func offActor<Value: Sendable>(_ call: OffActorCall, _ body: () async throws -> Value) async throws -> Value {
        guard outstandingOffActor.insert(call).inserted else {
            operationLog("off-actor \(call) still outstanding; attempt refused")
            throw DaemonFailure.controllerOperationFailed
        }
        defer { outstandingOffActor.remove(call) }
        return try await body()
    }

    /// The protection verifier off the actor. On return the generation is re-checked before the result is trusted.
    func verifyOffActor(_ expectation: ProtectionExpectation) async throws {
        try await offActor(.verify) { try await OffActor.verify(ports.verifier, expectation) }
        try check(expectation.resources.generation)
    }

    /// Inspects and removes what a generation owns, off the actor, re-checking `stillCurrent` after each adapter call.
    func removeOwnedResources(
        _ resource: GenerationResources, stillCurrent: () throws -> Void,
    ) async throws {
        let observed = try await offActor(.inspect) { try await OffActor.inspect(ports.reality, resource) }
        try stillCurrent()
        let owned = DaemonReconciliation.ownedResources(resource, observed: observed)
        try await offActor(.removeOwned) { try await OffActor.removeOwned(ports.reality, owned) }
        try stillCurrent()
    }
}
