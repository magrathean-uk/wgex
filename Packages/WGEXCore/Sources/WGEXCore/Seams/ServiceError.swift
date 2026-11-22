// SPDX-License-Identifier: MIT

/// Failures of ``ServiceControlling`` operations.
public enum ServiceError: Error, Codable, Sendable, Hashable {
    /// Refused by the host guard: Debug builds register only inside a VM
    /// (`kern.hv_vmm_present == 1`, ADR-017).
    case hostGuard
    /// The system refused the operation; the payload is the system error code.
    case system(code: Int)
    /// The operation is not available on this platform.
    case unsupported
}
