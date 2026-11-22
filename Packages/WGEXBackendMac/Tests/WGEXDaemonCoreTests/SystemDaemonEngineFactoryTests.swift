// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

private struct SystemDaemonEngineFactoryTests {
    #if WGEX_LAB_BUILD
        @Test(arguments: [EngineConfiguration.LogLevel.info, .debug, .error, .off])
        func `factory log clamp follows the compiled Lab flag`(level: EngineConfiguration.LogLevel) async throws {
            #if WGEX_LAB_BUILD
                let expected = level
            #else
                let expected = EngineConfiguration.LogLevel.info
            #endif
            let factory = SystemDaemonEngineFactory(logLevel: level, makeEngine: { configuration in
                #expect(configuration.logLevel == expected)
                throw HostTestError.injected
            })
            let configuration = EngineConfiguration(tun: .createUTun(mtu: 1280), bindInterfaceIndexV4: 1, bindInterfaceIndexV6: 1)
            await #expect(throws: HostTestError.self) { try await factory.create(configuration: configuration, generation: .initial) }
        }
    #endif
    @Test(arguments: [UInt32?.none, 0, 1], [UInt32?.none, 0, 1])
    func `both socket families must be bound before engine construction`(v4: UInt32?, v6: UInt32?) async throws {
        let trace = HostTrace()
        let factory = SystemDaemonEngineFactory(makeEngine: { _ in
            try trace.record("construct")
            throw HostTestError.injected
        })
        let configuration = EngineConfiguration(tun: .createUTun(mtu: 1420), bindInterfaceIndexV4: v4, bindInterfaceIndexV6: v6)
        if v4 == 1, v6 == 1 {
            await #expect(throws: HostTestError.self) {
                try await factory.create(configuration: configuration, generation: .initial)
            }
            #expect(trace.calls == ["construct"])
        } else {
            await #expect(throws: DaemonFailure.hostUnboundInterfaces) {
                try await factory.create(configuration: configuration, generation: .initial)
            }
            #expect(trace.calls.isEmpty)
        }
    }

    @Test
    func `production construction disables requested debug logging`() async throws {
        let factory = SystemDaemonEngineFactory(makeEngine: { configuration in
            #expect(configuration.logLevel == .info)
            throw HostTestError.injected
        })
        let configuration = EngineConfiguration(
            tun: .createUTun(mtu: 1280), bindInterfaceIndexV4: 1, bindInterfaceIndexV6: 1, logLevel: .debug,
        )
        await #expect(throws: HostTestError.self) { try await factory.create(configuration: configuration, generation: .initial) }
    }
}
