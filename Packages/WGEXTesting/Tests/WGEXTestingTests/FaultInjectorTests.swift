// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXTesting

private struct FaultInjectorTests {
    @Test
    func `armed faults are consumed in order and counted`() {
        let faults = FaultInjector()
        faults.arm("start", error: TunnelError.timedOut, times: 2)
        #expect(faults.fault(at: "stop", as: TunnelError.self) == nil)
        #expect(faults.fault(at: "start", as: ServiceError.self) == nil)
        #expect(faults.fault(at: "start", as: TunnelError.self) == .timedOut)
        #expect(faults.fault(at: "start", as: TunnelError.self) == .timedOut)
        #expect(faults.fault(at: "start", as: TunnelError.self) == nil)
        #expect(faults.triggerCount(at: "start") == 2)
    }

    @Test
    func `disarm clears a point`() {
        let faults = FaultInjector()
        faults.arm("install", error: TunnelError.permissionDenied)
        faults.disarm("install")
        #expect(faults.fault(at: "install", as: TunnelError.self) == nil)
    }
}
