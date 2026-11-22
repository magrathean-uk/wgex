// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import Foundation
    import WGEXDaemonProtocol

    /// Host-safety guard compiled into the daemon (ADR-017, P0-18). Mutating
    /// daemon paths run only when all three hold:
    ///
    /// 1. the module was compiled with `WGEX_LAB_BUILD` (`just lab build` only);
    /// 2. `sysctl kern.hv_vmm_present == 1`;
    /// 3. ``markerPath`` exists as a regular file owned by root with mode 0644.
    ///
    /// None of the three can be supplied through the environment at run time.
    public struct LabGuard: Sendable {
        /// Root-owned marker created by the lab provisioning script.
        public static let markerPath = "/var/db/wgex-lab-host"

        /// True when this module was compiled with `WGEX_LAB_BUILD`.
        public static var isLabBuild: Bool {
            #if WGEX_LAB_BUILD
                true
            #else
                false
            #endif
        }

        private let compiledForLab: Bool
        private let sysctl: any SysctlReading
        private let marker: any LabMarkerInspecting

        /// The guard for the running process.
        public init() {
            self.init(compiledForLab: Self.isLabBuild, sysctl: SystemSysctl(), marker: SystemLabMarkerInspector())
        }

        /// Test seam: the compile-time condition is injectable only inside this package.
        package init(compiledForLab: Bool, sysctl: any SysctlReading, marker: any LabMarkerInspecting) {
            self.compiledForLab = compiledForLab
            self.sysctl = sysctl
            self.marker = marker
        }

        /// ``isLabHost()`` for the running process.
        public static func isLabHost() -> Bool {
            LabGuard().isLabHost()
        }

        /// True only when all three conditions hold. Checks stop at the first
        /// failure, so a non-lab build never reads the sysctl or the file system.
        public func isLabHost() -> Bool {
            guard compiledForLab, HypervisorPresence.isVirtualMachine(sysctl), let status = marker.status(atPath: Self.markerPath) else {
                return false
            }
            return status.isRegularFile && status.ownerUID == 0 && status.permissions == 0o644
        }
    }

#endif
