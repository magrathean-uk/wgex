// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore

/// Facts obtained from the accepted connection; never decoded from a request.
public struct VerifiedPeerIdentity: Sendable, Hashable {
    public enum CodeSigningVerdict: Sendable, Hashable { case requirementSatisfied, rejected }
    public let uid: uid_t
    public let pid: pid_t
    /// Public NSXPC audit-session summary, not a user-supplied token.
    public let auditSessionID: UInt32
    public let codeSigningVerdict: CodeSigningVerdict
    /// The accepted connection's kernel audit token (`audit_token_t` bytes). Code identity (app versus CLI) is taken from
    /// it, never from `pid`, so a reused process ID cannot pass as the app; nil fails closed to "not the app".
    public let auditToken: Data?

    public init(uid: uid_t, pid: pid_t, auditSessionID: UInt32, codeSigningVerdict: CodeSigningVerdict, auditToken: Data? = nil) {
        self.uid = uid
        self.pid = pid
        self.auditSessionID = auditSessionID
        self.codeSigningVerdict = codeSigningVerdict
        self.auditToken = auditToken
    }
}

/// Exported by the client. The secret callback is installed only by the app.
public struct XPCClientCallbacks: Sendable {
    public let event: @Sendable (Data) async -> Void
    public let provideSecrets: @Sendable (UUID) async throws -> Data
    public let invalidated: @Sendable () async -> Void

    public init(
        event: @escaping @Sendable (Data) async -> Void = { _ in },
        provideSecrets: @escaping @Sendable (UUID) async throws -> Data = { _ in throw DaemonError.secretsUnavailable },
        invalidated: @escaping @Sendable () async -> Void = {},
    ) {
        self.event = event
        self.provideSecrets = provideSecrets
        self.invalidated = invalidated
    }
}

/// Client half. Construction must not open a Mach service; connect is explicit.
public protocol XPCTransport: Sendable {
    func connect(callbacks: XPCClientCallbacks) async throws
    func send(_ envelope: Data, secrets: Data?) async throws -> Data
    func invalidate() async
}

/// Daemon half, shared by the real adapter and the in-memory transport.
public protocol XPCDaemonTransport: Sendable {
    func accept(peer: VerifiedPeerIdentity, callbacks: XPCClientCallbacks) async throws -> UUID
    func receive(connectionID: UUID, envelope: Data, secrets: Data?) async -> Data
    func disconnect(connectionID: UUID) async
}

// No NSXPCConnection, system registration or Keychain access.
#if DEBUG || WGEX_LAB_BUILD
    /// Connects injected ports in memory without opening a Mach service.
    public actor InMemoryXPCTransport: XPCTransport {
        private let daemon: any XPCDaemonTransport
        private let peer: VerifiedPeerIdentity
        private var connectionID: UUID?
        private var callbacks: XPCClientCallbacks?

        /// Creates the inert fixture with explicitly supplied state.
        public init(daemon: any XPCDaemonTransport, peer: VerifiedPeerIdentity) {
            self.daemon = daemon
            self.peer = peer
        }

        /// Accepts the injected peer on the in-memory daemon transport.
        public func connect(callbacks: XPCClientCallbacks) async throws {
            if let connectionID {
                await daemon.disconnect(connectionID: connectionID)
            }
            connectionID = try await daemon.accept(peer: peer, callbacks: callbacks)
            self.callbacks = callbacks
        }

        /// Delivers fixture input through the injected port.
        public func send(_ envelope: Data, secrets: Data?) async throws -> Data {
            guard let connectionID else { throw DaemonError.disconnected }
            return await daemon.receive(connectionID: connectionID, envelope: envelope, secrets: secrets)
        }

        /// Disconnects only this fixture transport.
        public func invalidate() async {
            let old = connectionID
            connectionID = nil
            if let old {
                await daemon.disconnect(connectionID: old)
            }
        }

        /// Simulates interruption or daemon exit, including the exported callback.
        public func simulateInterruption() async {
            await invalidate()
            await callbacks?.invalidated()
        }
    }
#endif

/// Injected monotonic time and cancellable delays; tests never wait on wall time.
public struct XPCClock: Sendable {
    /// Shared kernel clock, including sleep, used by both the daemon and its clients.
    public static var continuousSeconds: TimeInterval {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        return Double(mach_continuous_time()) * Double(timebase.numer) / Double(timebase.denom) / 1e9 // spellchecker:disable-line
    }

    public let now: @Sendable () -> TimeInterval
    public let sleep: @Sendable (Duration) async throws -> Void

    public init(now: @escaping @Sendable () -> TimeInterval, sleep: @escaping @Sendable (Duration) async throws -> Void) {
        self.now = now
        self.sleep = sleep
    }

    public static let continuous = XPCClock(
        now: { XPCClock.continuousSeconds },
        sleep: { try await ContinuousClock().sleep(for: $0) },
    )
}
