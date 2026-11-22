// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// The executable supplies WGEXDiagnostics without adding a backend-to-diagnostics package edge.
/// Each call receives an already intersected profile set; empty always means no profiles.
public protocol DaemonDiagnosticsProviding: Sendable {
    func record(_ event: DaemonServiceEvent) async -> RedactedLogLine?
    /// Retains one engine (tunnel) log line for the owning profile, or the daemon-wide ring when nil. The text stays inside
    /// the ring and reaches a client only through `logs`, redacted; it is never published as an event or written to a log.
    func recordEngine(_ message: String, date: Date, profileID: UUID?)
    /// Registers installed metadata before any global section export.
    func register(_ profile: TunnelProfile)
    /// Registers borrowed secret bytes in the redactor without retaining plaintext.
    func registerSecretWire(_ wire: borrowing SecretBytes) throws
    /// Retries registration before exporting diagnostics.
    func setPreparation(_ action: @escaping @Sendable () async throws -> Void)
    /// Supplies the concrete adapter's unavailable-section error without importing its module into Core.
    func sectionUnavailableFailure() -> any Error
    /// Fails exports closed after an incomplete registration.
    func disableExports()
    func logs(since: Date?, limit: Int, visibleProfileIDs: Set<UUID>) async throws -> [RedactedLogLine]
    func bundle(_ request: DiagnosticsRequest, visibleProfileIDs: Set<UUID>) async throws -> DiagnosticsBundle
}

public struct UnavailableDaemonDiagnostics: DaemonDiagnosticsProviding {
    public init() {}
    public func logs(since: Date?, limit: Int, visibleProfileIDs: Set<UUID>) async throws -> [RedactedLogLine] {
        throw DaemonFailure.integrationNotImplemented("diagnostics")
    }

    public func bundle(_ request: DiagnosticsRequest, visibleProfileIDs: Set<UUID>) async throws -> DiagnosticsBundle {
        throw DaemonFailure.integrationNotImplemented("diagnostics")
    }
}

public extension DaemonDiagnosticsProviding {
    /// The unavailable production port keeps exports closed using its existing failure category.
    func sectionUnavailableFailure() -> any Error {
        DaemonFailure.integrationNotImplemented("diagnostics")
    }

    /// An unavailable diagnostics port has no export state or registrations.
    func register(_: TunnelProfile) {}
    /// An unavailable diagnostics port never retains secret material.
    func registerSecretWire(_: borrowing SecretBytes) throws {}
    /// An unavailable diagnostics port cannot export sections.
    func setPreparation(_: @escaping @Sendable () async throws -> Void) {}
    /// An unavailable diagnostics port is already closed.
    func disableExports() {}
    func record(_ event: DaemonServiceEvent) async -> RedactedLogLine? {
        nil
    }

    /// An unavailable diagnostics port retains no engine text.
    func recordEngine(_: String, date _: Date, profileID _: UUID?) {}
}

/// Structured diagnostics shared by ordinary and Lab compositions; no arbitrary error text is accepted.
public enum DaemonDiagnostics {
    /// Which ownership check refused or adopted a resource (M1-17, M1-18). Lab builds alone carry the log text, so
    /// Release ships no ownership vocabulary.
    public enum OwnershipEvent: Sendable, CaseIterable {
        case tunnelIdentityDrift
        case tunnelIdentityMissing
        case tunnelDescriptorMissing
        case canaryIdentityDrift
        case routeInterfaceDrift
        case deviceInterfaceDrift
        case canaryInterfaceMissing
        case foreignRoute
        case tunnelRouteMissing
        case canaryRouteMissing
        case policyMismatch
        case dnsUnverified
        case engineInterfaceMismatch
        case engineInterfaceMissing
        case canaryAdopted
        case canaryReplaced
    }

    /// Crash-recovery anchor steps (M1-20): the blocking anchor was rendered and loaded in one replace, a recovery
    /// policy load left that anchor untouched, or the read-back and canary verified it. Only Lab builds log them.
    public enum RecoveryStep: Sendable, CaseIterable {
        case kept
        case rendered
        case verified
    }
}
