// SPDX-License-Identifier: MIT

#if WGEX_LAB_BUILD
    import Foundation
    import Testing
    @testable import WGEXDaemonCore
    import WGEXDaemonCoreTesting
    import WGEXDaemonProtocol

    private struct LabGuardTests {
        private struct FixedSysctl: SysctlReading {
            let value: Int64?
            func integer(named name: String) -> Int64? {
                name == HypervisorPresence.sysctlName ? value : nil
            }
        }

        private struct FakeMarker: LabMarkerInspecting {
            let status: LabMarkerStatus?
            var contents = Data()

            func status(atPath path: String) -> LabMarkerStatus? {
                path == LabGuard.markerPath ? status : nil
            }

            func contents(atPath path: String, limit: Int) -> Data? {
                path == LabGuard.markerPath && contents.count <= limit ? contents : nil
            }
        }

        private static let goodMarker = LabMarkerStatus(isRegularFile: true, ownerUID: 0, permissions: 0o644)

        private static var hostIsVirtualMachine: Bool {
            HypervisorPresence.isVirtualMachine(SystemSysctl())
        }

        @Test(arguments: [false, true], [false, true])
        func `all three conditions are required`(compiled: Bool, virtualMachine: Bool) {
            for markerPresent in [false, true] {
                let labGuard = LabGuard(
                    compiledForLab: compiled,
                    sysctl: FixedSysctl(value: virtualMachine ? 1 : 0),
                    marker: FakeMarker(status: markerPresent ? Self.goodMarker : nil),
                )
                #expect(labGuard.isLabHost() == (compiled && virtualMachine && markerPresent))
            }
        }

        @Test(arguments: [
            LabMarkerStatus(isRegularFile: false, ownerUID: 0, permissions: 0o644),
            LabMarkerStatus(isRegularFile: true, ownerUID: 501, permissions: 0o644),
            LabMarkerStatus(isRegularFile: true, ownerUID: 0, permissions: 0o666),
            LabMarkerStatus(isRegularFile: true, ownerUID: 0, permissions: 0o600),
            LabMarkerStatus(isRegularFile: true, ownerUID: 0, permissions: 0o4644),
        ])
        func `the marker must be a root-owned 0644 file`(status: LabMarkerStatus) {
            let labGuard = LabGuard(compiledForLab: true, sysctl: FixedSysctl(value: 1), marker: FakeMarker(status: status))
            #expect(!labGuard.isLabHost())
        }

        @Test(arguments: [Int64?.none, 0, 2])
        func `only hv_vmm_present equal to one counts`(value: Int64?) {
            let labGuard = LabGuard(compiledForLab: true, sysctl: FixedSysctl(value: value), marker: FakeMarker(status: Self.goodMarker))
            #expect(!labGuard.isLabHost())
        }

        @Test
        func `hooks come from the marker as JSON`() {
            let json = Data(#"{"crashAt":"afterRoutes","allowDevPath":true,"unknown":1}"#.utf8)
            let labGuard = LabGuard(
                compiledForLab: true,
                sysctl: FixedSysctl(value: 1),
                marker: FakeMarker(status: Self.goodMarker, contents: json),
            )
            #expect(labGuard.labHooks(marker: FakeMarker(status: Self.goodMarker, contents: json)) == LabHooks(
                crashAt: "afterRoutes",
                allowDevPath: true,
            ))
            let empty = LabGuard(
                compiledForLab: true,
                sysctl: FixedSysctl(value: 1),
                marker: FakeMarker(status: Self.goodMarker, contents: Data("\n".utf8)),
            )
            #expect(empty.labHooks(marker: FakeMarker(status: Self.goodMarker, contents: Data("\n".utf8))) == LabHooks())
            let invalid = LabGuard(
                compiledForLab: true,
                sysctl: FixedSysctl(value: 1),
                marker: FakeMarker(status: Self.goodMarker, contents: Data("{".utf8)),
            )
            #expect(invalid.labHooks(marker: FakeMarker(status: Self.goodMarker, contents: Data("{".utf8))) == nil)
        }

        @Test
        func `hooks are ignored off a lab host`() {
            let json = Data(#"{"crashAt":"afterRoutes"}"#.utf8)
            let labGuard = LabGuard(
                compiledForLab: false,
                sysctl: FixedSysctl(value: 1),
                marker: FakeMarker(status: Self.goodMarker, contents: json),
            )
            #expect(labGuard.labHooks(marker: FakeMarker(status: Self.goodMarker, contents: json)) == nil)
        }

        @Test(.enabled(if: !hostIsVirtualMachine, "proves the guard on a physical host"))
        func `this host is never a lab host`() {
            // A lab-compiled core must still refuse this physical host.
            #expect(!LabGuard.isLabHost())
            #expect(!LabGuard().isLabHost())
            let forcedBuild = LabGuard(compiledForLab: true, sysctl: SystemSysctl(), marker: SystemLabMarkerInspector())
            #expect(!forcedBuild.isLabHost())
        }
    }

#endif
