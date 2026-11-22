// SPDX-License-Identifier: MIT

/// Failures reported by the daemon's system ports (routes, DNS, pf, resolver).
public enum DaemonPortError: Error, Codable, Sendable, Hashable {
    /// The system rejected the change; the payload is an `errno`-style code.
    case system(code: Int32)
    /// The item is not owned by this generation and was left alone.
    case notOwned
    /// The operation exceeded its deadline.
    case timedOut
    /// Nothing answered (resolver).
    case noAnswer
}
