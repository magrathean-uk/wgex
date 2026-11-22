// SPDX-License-Identifier: MIT
import Foundation
import WGEXDaemonProtocol

/// The production adapter has no executable or environment override.
public struct SystemPacketFilterSystem: PacketFilterSystem {
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {}

    /// Gates execution on the actual child PID being durably journalled.
    public func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.pfUnavailable }
            #endif
            return try await PFProcessExecutor(executable: URL(fileURLWithPath: "/sbin/pfctl"))
                .enable(deadline: deadline, beforeExec: beforeExec)
        #else
            throw DaemonFailure.pfUnavailable
        #endif
    }

    /// Runs the packet-filter operation under the supplied deadline.
    public func run(arguments: [String], input: Data, deadline: TimeInterval) async throws -> PFCommandResult {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.pfUnavailable }
            #endif
            return try await PFProcessExecutor(executable: URL(fileURLWithPath: "/sbin/pfctl"))
                .run(arguments: arguments, input: input, deadline: deadline)
        #else
            throw DaemonFailure.pfUnavailable
        #endif
    }
}
