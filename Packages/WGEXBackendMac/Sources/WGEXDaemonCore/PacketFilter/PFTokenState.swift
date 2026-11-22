// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// An enable child is held before execution until this record is durable.
public struct PFEnableAttempt: Codable, Sendable, Hashable {
    /// Kernel boot identity prevents PID reuse across boots from claiming foreign references.
    public let bootSession: UUID
    /// Actual child PID, preserved across exec into pfctl.
    public let pid: Int32
    /// Wall time of the write-ahead operation; diagnostic metadata only.
    public let at: Date
    /// Creates an attempt for an injected or suspended child.
    public init(bootSession: UUID, pid: Int32, at: Date) {
        self.bootSession = bootSession; self.pid = pid; self.at = at
    }
}

/// Token ownership and pending compensation are persisted atomically.
public struct PFTokenState: Codable, Sendable, Hashable {
    /// Only a numeric token returned by pfctl or proved by an enable attempt.
    public var token: String?
    /// Boot in which the token was acquired; legacy tokens have no identity and are discarded.
    public var bootSession: UUID?
    /// Child process that acquired the current token; required for adoption or release.
    public var pid: Int32?
    /// An enable whose result has not yet been durably acknowledged.
    public var attempt: PFEnableAttempt?
    /// Creates ownership state, including legacy or empty records.
    public init(token: String? = nil, bootSession: UUID? = nil, pid: Int32? = nil, attempt: PFEnableAttempt? = nil) {
        self.token = token; self.bootSession = bootSession; self.pid = pid; self.attempt = attempt
    }
}

/// Read once by daemon composition and injected into the enforcer.
public enum SystemBootSession {
    /// Reads the kernel's immutable identity for the current boot, without changing sysctl state.
    public static func read() throws -> UUID {
        #if os(macOS)
            var size = 0
            guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size <= 128 else {
                throw DaemonFailure.pfUnavailable
            }
            var bytes = [CChar](repeating: 0, count: size)
            guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0,
                  let value = UUID(uuidString: String(
                      decoding: bytes.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
                      as: UTF8.self,
                  ))
            else { throw DaemonFailure.pfUnavailable }
            return value
        #else
            throw DaemonFailure.pfUnavailable
        #endif
    }
}
