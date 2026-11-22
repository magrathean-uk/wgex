// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public protocol DaemonClock: HealthClock {
    var wallNow: Date { get }
    /// Shared kernel continuous seconds in production; injected clocks keep tests in one time domain.
    var continuousNow: TimeInterval { get }
    func sleep(for duration: Duration) async throws
}

public extension DaemonClock {
    /// Uses the same kernel clock as XPC clients, rather than this controller's relative origin.
    var continuousNow: TimeInterval {
        XPCClock.continuousSeconds
    }
}

public struct ContinuousDaemonClock: DaemonClock {
    private let origin = ContinuousClock.now
    public init() {}
    public var now: Duration {
        origin.duration(to: ContinuousClock.now)
    }

    public var wallNow: Date {
        Date()
    }

    public func sleep(for duration: Duration) async throws {
        try await ContinuousClock().sleep(for: duration)
    }
}

public struct UnderlaySnapshot: Sendable, Hashable {
    public let v4: UInt32?
    public let v6: UInt32?
    public let resolvers: [String]
    public let interfaceNames: [String]
    public let interfaceV4Name: String?
    public let interfaceV6Name: String?
    /// Validated networks observed on the primary services, used for explicit LAN exemptions.
    public let lanSubnets: [IPAddressRange]
    /// True only when the primary IPv6 service supplies a default router; ULA addresses alone are insufficient.
    public let ipv6DefaultRouteAvailable: Bool
    /// Router from the primary IPv4 service; used only for the blocked TEST-NET canary.
    public let ipv4Router: String?
    /// A missing family still binds to the available physical interface, so an attempt can fail without looping into utun.
    public var socketV4: UInt32? {
        v4 ?? v6
    }

    public var socketV6: UInt32? {
        v6 ?? v4
    }

    public init(
        v4: UInt32?, v6: UInt32?, resolvers: [String], interfaceNames: [String],
        interfaceV4Name: String? = nil, interfaceV6Name: String? = nil, lanSubnets: [IPAddressRange] = [],
        ipv6DefaultRouteAvailable: Bool? = nil, ipv4Router: String? = nil,
    ) {
        self.ipv4Router = ipv4Router
        self.v4 = v4; self.v6 = v6; self.resolvers = resolvers; self.interfaceNames = interfaceNames
        self.interfaceV4Name = interfaceV4Name; self.interfaceV6Name = interfaceV6Name
        self.lanSubnets = Array(Set(lanSubnets.filter { $0.prefixLength > 0 }.map(\.network))).sorted()
        self.ipv6DefaultRouteAvailable = ipv6DefaultRouteAvailable ?? (v6 != nil)
    }
}

public struct PolicyModifiers: Sendable, Hashable {
    public let allowLAN: Bool
    public let captiveWindow: CaptiveWindowRecord?
    public let consoleUID: UInt32?
    public let underlay: UnderlaySnapshot
    /// The intended tunnel's excluded destinations, literal and resolved (DEC-087); empty without an intended tunnel.
    public let exclusions: [IPAddressRange]
    /// The intended tunnel's excluded local ports (DEC-126); empty without an intended tunnel.
    public let exclusionPorts: [PortExclusion]
    public init(
        allowLAN: Bool, captiveWindow: CaptiveWindowRecord?, consoleUID: UInt32?, underlay: UnderlaySnapshot,
        exclusions: [IPAddressRange] = [], exclusionPorts: [PortExclusion] = [],
    ) {
        self.allowLAN = allowLAN; self.captiveWindow = captiveWindow; self.consoleUID = consoleUID; self.underlay = underlay
        self.exclusions = exclusions; self.exclusionPorts = exclusionPorts
    }
}

/// Supplements PolicyEnforcing until Core's phase-0 policy shape carries modifiers and pf token management.
public protocol DaemonPolicyManaging: Sendable {
    /// Applies the policy using the canonical daemon failure taxonomy.
    func apply(_ policy: PacketFilterPolicy) async throws(DaemonFailure)
    /// Reports the last loaded policy.
    func current() async -> PacketFilterPolicy
    func setModifiers(_ modifiers: PolicyModifiers) async throws
    func acquireToken(existing: String?) async throws -> String
    func releaseToken(_ token: String) async throws
    func verification() async -> PFVerificationStatus
    func verifyEvaluation() async throws
    func configureProfile(_ profile: TunnelProfile) async throws
    /// Repairs an owned enable reference; ports without repair support fail closed.
    func repairLiveness(existingToken: String?, failure: any Error) async throws -> String
}

public extension DaemonPolicyManaging {
    /// A policy port without token-repair support cannot report repaired protection.
    func repairLiveness(existingToken _: String?, failure: any Error) async throws -> String {
        throw failure
    }
}

/// Engine creation must return the utun's identity immediately, before address configuration: name, index and this
/// process's descriptor recorded for the generation (M1-18).
public struct CreatedDaemonEngine: Sendable {
    public let engine: any EngineControlling
    public let identity: TunnelIdentity
    public init(engine: any EngineControlling, identity: TunnelIdentity) {
        self.engine = engine; self.identity = identity
    }
}

public protocol DaemonEngineCreating: Sendable {
    func create(configuration: EngineConfiguration, generation: Generation) async throws -> CreatedDaemonEngine
}

public protocol TunnelDeviceConfiguring: Sendable {
    func configure(_ identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16, generation: Generation) async throws
    func removeAddresses(_ identity: TunnelIdentity, generation: Generation) async throws
    /// Confirms the utun after this daemon's own configure and returns the recorded identity: a changed name or index,
    /// a closed descriptor or one reporting another name, or a missing assigned address fails closed (M1-18).
    func identity(afterConfiguring identity: TunnelIdentity) async throws -> TunnelIdentity
    /// The same confirmation plus the engine that holds the descriptor: it must exist and report the utun's name.
    func identity(afterConfiguring identity: TunnelIdentity, engine: any EngineControlling?) async throws -> TunnelIdentity
}

public extension TunnelDeviceConfiguring {
    /// A device port without a kernel identity reader has nothing further to confirm.
    func identity(afterConfiguring identity: TunnelIdentity) async throws -> TunnelIdentity {
        identity
    }

    /// A device port without a kernel identity reader holds no descriptor to confirm against an engine.
    func identity(afterConfiguring identity: TunnelIdentity, engine _: any EngineControlling?) async throws -> TunnelIdentity {
        try await self.identity(afterConfiguring: identity)
    }
}

public struct ProtectionExpectation: Sendable {
    public let resources: GenerationResources
    public let policy: PacketFilterPolicy
    public let engine: any EngineControlling
    public init(resources: GenerationResources, policy: PacketFilterPolicy, engine: any EngineControlling) {
        self.resources = resources; self.policy = policy; self.engine = engine
    }
}

/// Checks route ownership, DNS, engine liveness and the PF class already measured by the controller.
/// Returning normally means every check succeeded; a no-op implementation must never be used in production.
public protocol ProtectionVerifying: Sendable {
    func verify(_ expectation: ProtectionExpectation) async throws
}

/// Reality adapter must compare RTF_PROTO2, ifindex AND the interface fence (InterfaceFence), not just interface names.
/// The core filters observations before removal. The adapter must recheck identities immediately before each mutation
/// to close the inspect/remove race; disappearance and foreign replacement are harmless no-ops.
public protocol DaemonRealityInspecting: Sendable {
    func inspect(_ resources: GenerationResources) async throws -> DaemonRealitySnapshot
    func removeOwned(_ resources: GenerationResources) async throws
}

/// Fault and suspension points are before each journalled operation; tests never block a real adapter.
public protocol DaemonStepObserving: Sendable {
    func before(_ step: DaemonStep, generation: Generation) async throws
}

public struct UninterruptedDaemonSteps: DaemonStepObserving {
    public init() {}
    public func before(_: DaemonStep, generation _: Generation) async throws {
        try Task.checkCancellation()
    }
}

public struct DaemonPorts: Sendable {
    public let engineFactory: any DaemonEngineCreating
    public let routes: any DaemonRouteProgramming
    public let dns: any DaemonDNSConfiguring
    public let policy: any DaemonPolicyManaging
    public let resolver: any DaemonUnderlayResolving
    public let device: any TunnelDeviceConfiguring
    public let verifier: any ProtectionVerifying
    public let reality: any DaemonRealityInspecting
    public init(
        engineFactory: any DaemonEngineCreating, routes: any DaemonRouteProgramming, dns: any DaemonDNSConfiguring,
        policy: any DaemonPolicyManaging, resolver: any DaemonUnderlayResolving, device: any TunnelDeviceConfiguring,
        verifier: any ProtectionVerifying, reality: any DaemonRealityInspecting,
    ) {
        self.engineFactory = engineFactory; self.routes = routes; self.dns = dns; self.policy = policy
        self.resolver = resolver; self.device = device; self.verifier = verifier; self.reality = reality
    }
}
