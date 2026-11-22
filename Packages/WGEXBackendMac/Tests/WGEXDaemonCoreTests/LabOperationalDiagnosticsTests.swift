// SPDX-License-Identifier: MIT
#if WGEX_LAB_BUILD
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    @testable import WGEXDaemonCore
    import WGEXDaemonProtocol

    private struct LabOperationalDiagnosticsTests {
        @Test
        func `status diagnostics use the real adapter change gate and omit payloads`() async {
            let adapter = DaemonDiagnosticsAdapter(), lines = Mutex<[String]>([])
            let id = UUID()
            await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                var status = TunnelStatus.idle
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.sequence += 1; status.measuredAt = Date()
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) == nil)
                status.phase = .reasserting(.initial, reason: .endpointRotation); status.protection = .blocked
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.phase = .active(.initial); status.protection = .protected
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.phase = .failed(.profileNotFound(id), blockedByPolicy: false, needsSecrets: false)
                status.protection = .unknown
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.phase = .failed(.engine(code: -99), blockedByPolicy: false, needsSecrets: false)
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.phase = .captiveWindow(.initial, expires: Date())
                status.protection = .captiveWindow(expires: Date())
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
                status.phase = .idle; status.protection = .unsupported
                #expect(await adapter.record(.init(event: .status(status), profileID: id, ownerUID: 501)) != nil)
            }
            let output = lines.withLock { $0 }
            #expect(output == [
                "status: phase=idle protection=unprotected reason=none",
                "status: phase=reasserting protection=blocked reason=endpointRotation",
                "status: phase=active protection=protected reason=none",
                "status: phase=failed protection=unknown reason=profileNotFound",
                "status: phase=failed protection=unknown reason=engine",
                "status: phase=captivewindow protection=unprotected reason=none",
                "status: phase=idle protection=unknown reason=none",
            ])
            for line in output {
                #expect(line.range(of: "^status: phase=[a-z]+ protection=[a-z]+ reason=[A-Za-z]+$", options: .regularExpression) != nil)
                #expect(!line.contains(id.uuidString))
            }
        }

        @Test
        func `real policy verification emits fixed successful and missing anchor verdicts`() async throws {
            let journal = PFMemoryJournal(), system = PFScriptedSystem(journal: journal), lines = Mutex<[String]>([])
            let policy = try PolicyEnforcer(
                runner: PFCtl(system: system), journal: journal,
                context: PFContext(underlay: PFInterface("en0"), consoleUID: 501),
                canaryProbe: { await system.probe() },
            )
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                try await policy.apply(.error)
                try await policy.apply(.connected(interfaceName: "utun4", endpoints: []))
                await system.setMissingStock()
                await #expect(throws: (any Error).self) { _ = try await policy.acquireToken(existing: journal.readToken()) }
            }
            let verdicts = lines.withLock { $0.filter { $0.hasPrefix("verifier:") } }
            #expect(verdicts.contains("verifier: blocked"))
            #expect(verdicts.contains("verifier: protected"))
            #expect(verdicts.contains("verifier: anchorMissing"))
            for line in verdicts {
                #expect(line.range(of: "^verifier: [A-Za-z]+$", options: .regularExpression) != nil)
            }
        }

        @Test
        func `real token lifecycle emits all four fixed phrases without ownership data`() async throws {
            let journal = PFMemoryJournal(token: "99"), system = PFScriptedSystem(journal: journal)
            let lines = Mutex<[String]>([])
            let lifecycle = try PFTokenLifecycle(
                runner: PFCtl(system: system), journal: journal, bootSession: journal.readState().bootSession,
                onExternalRelease: {},
            )
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                let recovered = try #require(try await lifecycle.reconcile())
                try await lifecycle.release(recovered)
                let acquired = try await lifecycle.acquire()
                await system.setFailRelease()
                await #expect(throws: (any Error).self) { try await lifecycle.release(acquired) }
            }
            let output = lines.withLock { $0.filter { $0.hasPrefix("pf:") } }
            #expect(output == ["pf: token recovered", "pf: token released", "pf: token acquired", "pf: reference leaked"])
            for line in output {
                #expect(line.range(of: "^pf: (token (acquired|released|recovered)|reference leaked)$", options: .regularExpression) != nil)
            }
            #expect(lines.withLock { $0.contains("verifier: referenceLeaked") })
        }
    }
#endif
