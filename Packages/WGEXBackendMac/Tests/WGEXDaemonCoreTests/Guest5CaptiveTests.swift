// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct Guest5CaptiveTests {
    #if WGEX_LAB_BUILD
        @Test(arguments: [DaemonFailure.Code.captiveUnavailable, .captiveDNSFailed, .captiveRoutesFailed, .captivePolicyFailed])
        func `D8 typed stage survives the existing log vocabulary`(_ code: DaemonFailure.Code) {
            let fields = DaemonDiagnostics.fields(for: DaemonFailure(code: code))
            #expect(fields.type == "DaemonPortError" && fields.label == "system")
            #expect(fields.code == Int32(code.rawValue))
        }
    #endif

    @Test(arguments: [false, true])
    func `D8 an intended failed tunnel can open a captive window and restart when it closes`(_ expires: Bool) async throws {
        let h = try ControllerHarness(); try await h.install()
        h.trace.fail(at: "verify")
        await #expect(throws: (any Error).self) { _ = try await h.start() }
        #expect(await h.controller.engines.isEmpty)
        #expect(h.journal.snapshot().intent != nil)
        try await h.controller.openCaptiveWindow(seconds: 30, connectionUID: 501)
        let opened = await h.controller.status
        guard case .captiveWindow = opened.phase else { Issue.record("Captive window did not open"); return }
        h.clock.advance(.seconds(5)); try await h.controller.tick()
        #expect(await h.controller.status.phase == opened.phase)
        if expires {
            h.clock.advance(.seconds(25)); try await h.controller.tick()
            try await waitForCondition {
                if case .active = await h.controller.status.phase {
                    return true
                }; return false
            }
        } else {
            try await h.controller.closeCaptiveWindow()
        }
        guard case .active = await h.controller.status.phase else { Issue.record("Failed intent did not restart"); return }
        #expect(await h.controller.status.protection == .protected)
        #expect(h.journal.snapshot().captiveWindow == nil)
        await h.controller.cancelBackgroundWork()
    }

    @Test
    func `D8 captive admission without a live engine has a public typed category`() async throws {
        let h = try ControllerHarness()
        do {
            try await h.controller.openCaptiveWindow(seconds: 30, connectionUID: 501)
            Issue.record("Inactive captive window was accepted")
        } catch {
            let failure = try #require(error as? DaemonFailure)
            #expect(failure.code == 754)
            #expect(failure.wireError().presentation.cliName == "captiveUnavailable")
        }
        #expect(h.trace.calls.isEmpty)
    }

    @Test(arguments: ["dns.remove", "routes.remove", "pf.captive"])
    func `D8 actual captive transaction names the failing adapter and stays blocked`(_ point: String) async throws {
        let h = try ControllerHarness(); try await h.install(); _ = try await h.start()
        h.trace.fail(at: point)
        do {
            try await h.controller.openCaptiveWindow(seconds: 30, connectionUID: 501)
            Issue.record("Faulted captive window was accepted")
        } catch {
            let failure = try #require(error as? DaemonFailure)
            let category = point == "dns.remove" ? "captiveDNSFailed" : point == "routes.remove" ? "captiveRoutesFailed" : "captivePolicyFailed"
            #expect(failure.wireError().presentation.cliName == category)
        }
        #expect(await h.controller.status.protection == .blocked)
        #expect(h.journal.snapshot().captiveWindow == nil)
        await h.controller.cancelBackgroundWork()
    }
}
