// SPDX-License-Identifier: MIT

import Foundation

/// Reads integer sysctl values; injected so guards can be tested.
public protocol SysctlReading: Sendable {
    /// The value of `name`, or nil when it does not exist.
    func integer(named name: String) -> Int64?
}

/// `sysctlbyname` on the running system (read-only).
public struct SystemSysctl: SysctlReading {
    /// Creates a reader.
    public init() {}

    /// Reads a 32- or 64-bit integer sysctl.
    public func integer(named name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        switch size {
        case MemoryLayout<Int32>.size:
            return Int64(Int32(truncatingIfNeeded: value))
        case MemoryLayout<Int64>.size:
            return value
        default:
            return nil
        }
    }
}

/// Virtual-machine detection used by the host guards (ADR-017).
public enum HypervisorPresence {
    /// The sysctl that reports a hypervisor.
    public static let sysctlName = "kern.hv_vmm_present"

    /// True only when `kern.hv_vmm_present == 1`.
    public static func isVirtualMachine(_ sysctl: any SysctlReading) -> Bool {
        sysctl.integer(named: sysctlName) == 1
    }
}
