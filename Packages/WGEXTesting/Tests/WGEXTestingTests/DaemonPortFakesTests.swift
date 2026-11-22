// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXTesting

private struct DaemonPortFakesTests {
    @Test
    func `routes are owned per generation`() async throws {
        let table = FakeRouteTable()
        let route = RouteSpec(destination: "0.0.0.0", prefixLength: 1, interfaceName: "utun9")
        try await table.install([route], generation: .initial)
        #expect(await table.ownedRoutes() == [route])
        await #expect(throws: DaemonPortError.notOwned) { try await table.removeRoutes(of: Generation(rawValue: 9)) }
        try await table.removeRoutes(of: .initial)
        #expect(await table.ownedRoutes().isEmpty)
    }

    @Test
    func `DNS is withdrawn only by the publishing generation`() async throws {
        let dns = FakeDNSConfigurator()
        let configuration = DNSConfiguration(servers: ["10.0.0.1"], searchDomains: [], matchDomains: [])
        try await dns.apply(configuration, generation: .initial)
        await #expect(throws: DaemonPortError.notOwned) { try await dns.remove(generation: Generation(rawValue: 2)) }
        #expect(await dns.current() == configuration)
        try await dns.remove(generation: .initial)
        #expect(await dns.current() == nil)
    }

    @Test
    func `policy history is kept and faults are honoured`() async throws {
        let policy = FakePolicyEnforcer()
        #expect(await policy.current() == .disconnected)
        try await policy.apply(.connecting(resolvers: ["192.0.2.53"], endpoints: ["198.51.100.1"]))
        try await policy.apply(.lockdown)
        #expect(policy.history.count == 2)
        policy.faults.arm("apply", error: DaemonPortError.system(code: 1))
        await #expect(throws: DaemonPortError.system(code: 1)) { try await policy.apply(.error) }
        #expect(await policy.current() == .lockdown)
    }

    @Test
    func `resolver answers and records queries`() async throws {
        let resolver = FakeUnderlayResolver(answers: ["peer.test.wgex": ["198.51.100.7"]])
        #expect(try await resolver.resolve(host: "peer.test.wgex", interfaceIndex: 4) == ["198.51.100.7"])
        await #expect(throws: DaemonPortError.noAnswer) { try await resolver.resolve(host: "missing.test.wgex", interfaceIndex: 4) }
        #expect(resolver.receivedQueries.map(\.interfaceIndex) == [4, 4])
    }
}
