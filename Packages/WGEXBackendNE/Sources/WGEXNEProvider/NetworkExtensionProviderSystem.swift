// SPDX-License-Identifier: MIT

import Foundation
import Network
import NetworkExtension
import Synchronization
import WGEXCore

/// Confines the provider and all NE settings to MainActor. Host tests never create this adapter.
@MainActor
public final class NetworkExtensionProviderSystem: ProviderSystem {
    private weak var provider: NEPacketTunnelProvider?
    private let descriptorFinder: @Sendable () throws -> Int32
    private var monitor: NWPathMonitor?
    private var settingsRevision: UInt64 = 0

    public init(provider: NEPacketTunnelProvider, descriptorFinder: @escaping @Sendable () throws -> Int32) {
        self.provider = provider; self.descriptorFinder = descriptorFinder
    }

    @MainActor public func apply(_ settings: NESettings?) async throws {
        guard let provider else { throw TunnelError.backendUnavailable }
        settingsRevision &+= 1
        let revision = settingsRevision
        let completion = SettingsCompletion()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
                guard !completion.wasCancelled else { return }
                provider.setTunnelNetworkSettings(
                    settings.map(NetworkExtensionSettingsAdapter.make),
                    completionHandler: Self.settingsHandler(completion: completion, revision: revision, owner: self),
                )
            }
        } onCancel: { completion.cancel() }
    }

    /// Built outside MainActor isolation and `@Sendable`: the SDK may call it on any queue, so it must not carry an
    /// isolation check. MainActor work hops explicitly.
    private nonisolated static func settingsHandler(
        completion: SettingsCompletion, revision: UInt64, owner: NetworkExtensionProviderSystem,
    ) -> @Sendable (any Error?) -> Void {
        { @Sendable [weak owner] error in
            completion.finish(error: error)
            Task { @MainActor in
                // A timed-out callback cannot restore a stopped generation's settings.
                if completion.wasCancelled, owner?.settingsRevision == revision {
                    owner?.provider?.setTunnelNetworkSettings(nil) { @Sendable _ in }
                }
            }
        }
    }

    public func findUTunDescriptor() throws -> Int32 {
        try descriptorFinder()
    }

    public func setReasserting(_ value: Bool) {
        provider?.reasserting = value
    }

    public func cancel(_ error: TunnelError) {
        provider?.cancelTunnelWithError(error)
    }

    /// Engine timers stay alive; controller-owned statistics timers are cancelled separately.
    public func quiesceTimers(_: Bool) {}

    public func paths() -> AsyncStream<ProviderPath> {
        monitor?.cancel()
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
        self.monitor = monitor
        let (stream, continuation) = AsyncStream<ProviderPath>.makeStream(bufferingPolicy: .bufferingNewest(8))
        monitor.pathUpdateHandler = { path in
            continuation.yield(ProviderPath(
                satisfied: path.status == .satisfied,
                interfaceIndex: path.availableInterfaces.first.map { UInt32($0.index) },
            ))
        }
        continuation.onTermination = { _ in monitor.cancel() }
        monitor.start(queue: DispatchQueue(label: "wgex.provider.path"))
        return stream
    }
}

/// Synchronises one callback against cancellation, including cancellation before continuation installation.
private final class SettingsCompletion: Sendable {
    private struct State {
        var continuation: CheckedContinuation<Void, any Error>?
        var cancelled = false
        var finished = false
    }

    private let state = Mutex(State())
    var wasCancelled: Bool {
        state.withLock { $0.cancelled }
    }

    func install(_ continuation: CheckedContinuation<Void, any Error>) {
        let cancelled = state.withLock { state in
            if state.cancelled {
                return true
            }
            state.continuation = continuation
            return false
        }
        if cancelled {
            continuation.resume(throwing: CancellationError())
        }
    }

    func finish(error: any Error?) {
        let continuation = state.withLock { state in
            guard !state.finished else { return CheckedContinuation<Void, any Error>?.none }
            state.finished = true
            let continuation = state.continuation; state.continuation = nil
            return continuation
        }
        if let error {
            continuation?.resume(throwing: error)
        } else {
            continuation?.resume()
        }
    }

    func cancel() {
        let continuation = state.withLock { state in
            state.cancelled = true
            let continuation = state.continuation; state.continuation = nil
            return continuation
        }
        continuation?.resume(throwing: CancellationError())
    }
}
