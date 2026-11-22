// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Testing
    @testable import WGEXDaemonCore
    import WGEXDaemonProtocol
    import WGEXDiagnostics

    private struct DiagnosticsSnapshotOrderingTests {
        @Test(arguments: [false, true])
        func `unavailable PF short circuits routes and DNS with sectionUnavailable`(oversized: Bool) async throws {
            let trace = HostTrace()
            let adapter = DaemonDiagnosticsAdapter.system(snapshot: {
                try await DaemonSystemSnapshot.collect(packetFilter: {
                    try trace.record("pf")
                    return PFCommandResult(status: oversized ? 0 : 3, stdout: oversized ? String(repeating: "x", count: (1 << 20) + 1) : "")
                }, routes: { try trace.record("routes"); return Data() }, dns: {
                    try trace.record("dns"); throw HostTestError.injected
                })
            })
            await #expect(throws: DiagnosticsError.sectionUnavailable) {
                try await adapter.bundle(.init(includeLogs: false, since: nil, profileIDs: []), visibleProfileIDs: [])
            }
            #expect(trace.calls == ["pf"])
        }

        @Test
        func `available snapshot probes PF then routes then DNS`() async throws {
            let trace = HostTrace()
            _ = try await DaemonSystemSnapshot.collect(packetFilter: {
                try trace.record("pf"); return PFCommandResult()
            }, routes: { try trace.record("routes"); return Data() }, dns: { try trace.record("dns"); return "" })
            #expect(trace.calls == ["pf", "routes", "dns"])
        }

        @Test
        func `deallocated registry preparation retains the concrete sectionUnavailable error`() async throws {
            let harness = try ControllerHarness(), adapter = DaemonDiagnosticsAdapter()
            var registry: ProfileRegistry? = try ProfileRegistry(
                repository: DirectoryProfileRepository(directory: harness.directory), secrets: harness.store, bundles: harness.store,
            )
            let preparation = try #require(registry).diagnosticsPreparation(unavailable: adapter.sectionUnavailableFailure())
            registry = nil
            await #expect(throws: DiagnosticsError.sectionUnavailable) { try await preparation() }
        }
    }
#endif
