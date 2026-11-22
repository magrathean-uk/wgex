// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXEngineInterface

private struct EngineErrorTests {
    @Test(arguments: [
        (Int32(-1), EngineError.invalidArgument), (-2, .outOfMemory), (-3, .invalidHandle), (-4, .tun),
        (-5, .bind), (-6, .config), (-7, .up), (-8, .state), (-9, .deviceClosed), (-99, .internal), (-42, .unknown(code: -42)),
    ])
    func `C codes map to errors`(code: Int32, expected: EngineError) {
        #expect(EngineError(code: code) == expected)
    }

    @Test
    func `success codes map to nil`() {
        #expect(EngineError(code: 0) == nil)
        #expect(EngineError(code: 7) == nil)
    }

    @Test
    func `constrained limits follow the memory governor`() {
        #expect(EngineConfiguration.ProcessLimits.constrained.memoryLimitBytes == 24 * 1024 * 1024)
        let configuration = EngineConfiguration(tun: .createUTun(mtu: 1420))
        #expect(configuration.transport == .udp)
        #expect(!configuration.mobileQuirks)
        #expect(configuration.logLevel == .info)
    }
}
