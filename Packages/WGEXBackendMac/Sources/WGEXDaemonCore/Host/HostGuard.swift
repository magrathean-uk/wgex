// SPDX-License-Identifier: MIT
import WGEXDaemonProtocol

/// Daemon entry policy, independent of lab hooks. Truth table (marker means valid root-owned marker):
///
/// Configuration | hypervisor 0 / missing | hypervisor 1, no marker | hypervisor 1, marker
/// Debug         | refuse, exit 0         | allow                   | allow
/// Release       | allow                  | allow                   | allow
/// Lab           | refuse, exit 78        | refuse, exit 78         | allow
///
/// Debug fails closed on an unreadable or unexpected sysctl. Release never calls the runtime guard.
public enum HostGuard {
    /// Build policy supplied explicitly by the entry point, injectable by tests.
    public enum Configuration: Sendable, CaseIterable { case debug, release, lab }

    /// Pure decision using a read-only injected sysctl. Marker validity includes ownership and mode checks.
    public static func permits(configuration: Configuration, sysctl: any SysctlReading, labMarkerValid: Bool = false) -> Bool {
        switch configuration {
        case .release: true
        case .debug: HypervisorPresence.isVirtualMachine(sysctl)
        case .lab: HypervisorPresence.isVirtualMachine(sysctl) && labMarkerValid
        }
    }

    /// Debug entry refusal, evaluated before constructing any system adapter.
    public static func refuseOwnerMac(sysctl: any SysctlReading = SystemSysctl()) -> Bool {
        !permits(configuration: .debug, sysctl: sysctl)
    }
}
