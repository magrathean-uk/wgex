// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import WGEXCore
import WGEXEngineInterface

public protocol ProviderClock: Sendable {
    /// Continuous elapsed seconds, including sleep, independently of the wall clock.
    var continuousNow: TimeInterval { get }
    var wallNow: Date { get }
    func sleep(until deadline: TimeInterval) async throws
}

public struct SystemProviderClock: ProviderClock {
    public init() {}
    public var continuousNow: TimeInterval {
        Self.continuousSeconds()
    }

    private static func continuousSeconds() -> Double {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(mach_continuous_time()) * Double(info.numer) / Double(info.denom) / 1e9 // spellchecker:disable-line
    }

    public var wallNow: Date {
        Date()
    }

    public func sleep(until deadline: TimeInterval) async throws {
        try await Task.sleep(for: .seconds(max(0, deadline - continuousNow)))
    }
}

public struct ProviderPath: Sendable, Hashable {
    public let satisfied: Bool
    public let interfaceIndex: UInt32?
    public init(satisfied: Bool, interfaceIndex: UInt32? = nil) {
        self.satisfied = satisfied; self.interfaceIndex = interfaceIndex
    }
}

public protocol ProviderSystem: Sendable {
    /// Completion or cancellation must resume promptly; a late system callback must not resurrect settings.
    func apply(_ settings: NESettings?) async throws
    func findUTunDescriptor() async throws -> Int32
    func paths() async -> AsyncStream<ProviderPath>
    func setReasserting(_ value: Bool) async
    func quiesceTimers(_ value: Bool) async
    /// Ends the tunnel from inside the extension (`cancelTunnelWithError`); NE then calls stop and on-demand may restart it.
    func cancel(_ error: TunnelError) async
}

public protocol ProviderProfileLoading: Sendable {
    func load(_ id: UUID) async throws -> TunnelProfile
}

public protocol ProviderSecretLoading: Sendable {
    func load(for profile: TunnelProfile) async throws -> ParsedSecrets
}

public protocol ProviderEndpointResolving: Sendable {
    /// Hostname resolution must use a physical interface, never the tunnel.
    func resolve(_ profile: TunnelProfile, interfaceIndex: UInt32?) async throws -> [PublicKey: Endpoint]
    /// Addresses of excluded host names (DEC-087), looked up before the tunnel settings apply. A name that fails or
    /// times out contributes nothing; only the literal exclusions then apply. Never throws.
    func resolveExclusions(_ names: [String], interfaceIndex: UInt32?) async -> [String: [IPAddressRange]]
}

public extension ProviderEndpointResolving {
    func resolveExclusions(_: [String], interfaceIndex _: UInt32?) async -> [String: [IPAddressRange]] {
        [:]
    }
}

/// Races through a bounded stream so a non-cooperative system callback cannot extend the deadline.
/// The adapter must discard a late successful apply after cancellation.
package func withProviderDeadlineValue<Value: Sendable>(
    clock: any ProviderClock, seconds: TimeInterval,
    operation: @escaping @Sendable () async throws -> Value,
) async throws -> Value {
    let deadline = clock.continuousNow + seconds
    let (stream, continuation) = AsyncStream<Result<Value, any Error>>.makeStream(bufferingPolicy: .bufferingOldest(1))
    let work = Task {
        do { try await continuation.yield(.success(operation())) }
        catch { continuation.yield(.failure(error)) }
    }
    let timer = Task {
        do { try await clock.sleep(until: deadline); continuation.yield(.failure(TunnelError.timedOut)) }
        catch { /* Cancellation ends the losing timer. */ }
    }
    defer { work.cancel(); timer.cancel(); continuation.finish() }
    return try await withTaskCancellationHandler {
        var iterator = stream.makeAsyncIterator()
        guard let result = await iterator.next() else { throw TunnelError.cancelled }
        return try result.get()
    } onCancel: { continuation.finish() }
}

/// Keeps the original Void deadline seam source-compatible.
package func withProviderDeadline(
    clock: any ProviderClock, seconds: TimeInterval,
    operation: @escaping @Sendable () async throws -> Void,
) async throws {
    try await withProviderDeadlineValue(clock: clock, seconds: seconds, operation: operation)
}
