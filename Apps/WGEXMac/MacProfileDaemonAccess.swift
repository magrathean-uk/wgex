// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore
    import WGEXUI

    /// Guards every profile-side daemon operation; local saves never depend on daemon liveness.
    @MainActor
    public final class MacProfileDaemonAccess {
        /// Supplied by the shell without retaining the composition through its operations.
        public var isReady: () -> Bool = { false }
        /// Reports a post-commit login-entry failure without undoing deletion.
        public var reportError: (any Error) -> Void = { _ in }
        /// Used only when the simulated adapter has no daemon snapshot.
        public var localStatus: () -> TunnelStatus = { .idle }
        private let permitted: Bool
        private let prepare: (TunnelProfile) async throws -> Void
        private let installOperation: (TunnelProfile) async throws -> Void
        private let removeOperation: (UUID, Bool) async throws -> Void
        private let statusOperation: () async throws -> TunnelStatus?

        /// Preparation binds local secret references only; the install closure may send XPC.
        public init(
            permitted: Bool, prepare: @escaping (TunnelProfile) async throws -> Void,
            install: @escaping (TunnelProfile) async throws -> Void,
            remove: @escaping (UUID, Bool) async throws -> Void,
            status: @escaping () async throws -> TunnelStatus? = { nil },
        ) {
            self.permitted = permitted; self.prepare = prepare
            installOperation = install; removeOperation = remove; statusOperation = status
        }

        /// A disconnected or unverified daemon is installed later by connect/startup.
        public func install(_ profile: TunnelProfile) async throws {
            guard permitted else { throw ServiceError.hostGuard }
            try await prepare(profile)
            guard isReady() else { return }
            // A daemon that disappears after readiness was checked must not roll back a local save.
            try? await MacDaemonBridge.mapDaemonError { try await installOperation(profile) }
        }

        /// Checks a fresh daemon phase before intent is journalled; guard refusal reaches no client call.
        public func checkRemoval(_: UUID) async throws {
            guard permitted else { throw ServiceError.hostGuard }
            let status = try await statusOperation() ?? localStatus()
            try MacProfileDeletionPolicy.check(status)
        }

        /// Rechecks phase at removal and preserves the daemon's original refusal category.
        public func remove(_ id: UUID, _ purge: Bool) async throws {
            try await checkRemoval(id)
            try await removeOperation(id, purge)
        }
    }
#endif
