// SPDX-License-Identifier: Apache-2.0 AND MIT

// Adapted from firezone swift/apple FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift at
// 229ac31b37b5fbde2961e7f87df8181abd7fd46f, Apache-2.0
// Copyright Firezone, Inc. Licensed under Apache-2.0; see Vendor/firezone/NOTICE and LICENSE.
import Foundation

public enum VPNStatus: String, Codable, Sendable, CaseIterable {
    case invalid, disconnected, connecting, connected, reasserting, disconnecting
}

/// Immutable copies cross the system boundary; a failed mutated NE object is discarded by reload.
public struct VPNManagerRecord: Sendable, Hashable {
    public let id: UUID
    public var configuration: ProtocolConfiguration
    public var name: String
    public var isEnabled: Bool
    public var isOnDemandEnabled: Bool
    public var status: VPNStatus
    /// Secret-free digest of the profile fields the running tunnel uses; nil for a manager saved before it existed.
    public var profileRevision: String?

    public init(
        id: UUID = UUID(), configuration: ProtocolConfiguration, name: String,
        isEnabled: Bool = true, isOnDemandEnabled: Bool = false, status: VPNStatus = .disconnected, profileRevision: String? = nil,
    ) {
        self.id = id; self.configuration = configuration; self.name = name
        self.isEnabled = isEnabled; self.isOnDemandEnabled = isOnDemandEnabled; self.status = status
        self.profileRevision = profileRevision
    }

    /// A manager whose tunnel is up or coming up.
    package static func isLive(_ status: VPNStatus) -> Bool {
        status == .connecting || status == .connected || status == .reasserting
    }
}

public struct VPNStatusEvent: Sendable {
    public let managerID: UUID
    public let sequence: UInt64
    public let status: VPNStatus

    public init(managerID: UUID, sequence: UInt64, status: VPNStatus) {
        self.managerID = managerID; self.sequence = sequence; self.status = status
    }
}

/// No system implementation is constructed implicitly. Tests supply an in-memory actor.
public protocol VPNManagerSystem: Sendable {
    func loadAll() async throws -> [VPNManagerRecord]
    func save(_ record: VPNManagerRecord) async throws
    func remove(_ id: UUID) async throws
    func start(_ id: UUID, transport: UUID?) async throws
    func stop(_ id: UUID) async throws
    /// Starts a manager that `stop` has confirmed down and returns only once the system reports it connected after this
    /// start, judged by `StartObservation`. The waiter is armed and the current status read in the same isolated step as
    /// the start request, so a connection faster than any status event is never missed, and it never depends on
    /// `statusEvents()`. Throws `TunnelError.cancelled` when the manager no longer carries `revision` (a newer save
    /// superseded the edit) or the caller is cancelled, the start request's own error when it is refused, and any other
    /// error when the manager went down again after this start. No timer ends it.
    func startConfirmed(_ id: UUID, revision: String?) async throws
    func statusEvents() async -> AsyncStream<VPNStatusEvent>
    func sendProviderMessage(_ id: UUID, data: Data) async throws -> Data
}

/// How a restart's confirmation reads each status of the restarted manager from its start request on. Connected
/// confirms it. A manager that has been seen coming up (or going down) since the start and is then disconnected has
/// failed; a disconnected status before that is the stopped manager the start began from, not a failure. Invalid means
/// the configuration is gone, so the start cannot succeed. Reasserting alone is never proof of the restart.
package struct StartObservation: Sendable {
    package enum Outcome: Sendable, Equatable {
        case connected, failed
    }

    private var wentUp = false

    package init() {}

    package mutating func observe(_ status: VPNStatus) -> Outcome? {
        switch status {
        case .connected: return .connected
        case .invalid: return .failed
        case .disconnected: return wentUp ? .failed : nil
        case .connecting, .reasserting, .disconnecting:
            wentUp = true
            return nil
        }
    }
}
