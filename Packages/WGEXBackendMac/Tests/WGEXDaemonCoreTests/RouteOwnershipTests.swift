// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct RouteOwnershipTests {
    @Test(arguments: ["add", "delete", "change", "get"], [4, 6])
    func `independent Darwin corpus decodes IPv4 IPv6 compact masks and ownership`(operation: String, version: Int) throws {
        let text = try NetworkPortHarness.fixture("RouteMessages/\(operation)-v\(version).hex")
        let bytes = try text.split(whereSeparator: \.isWhitespace).map { word in try #require(UInt8(word, radix: 16)) }
        let message = try RouteMessageCodec.parse(Data(bytes))
        #expect(message.pid == 4321); #expect(message.sequence == 17); #expect(message.index == 7)
        #expect(message.hasOwnershipMark); #expect(message.error == 0)
        let route = RouteSpec(destination: version == 4 ? "128.0.0.0" : "8000::", prefixLength: 1, interfaceName: "utun7")
        #expect(message.matches(route, index: 7))
        #expect(!message.matches(route, index: 8))
        #expect(message.addresses[1]?.count == 13)
    }

    @Test(arguments: RouteOperation.allCases, ["0.0.0.0/1", "::/1", "2001:db8::/64", "192.0.2.1/32", "2001:db8::1/128"])
    func `builder supports every operation without escape gateways`(operation: RouteOperation, cidr: String) throws {
        let range = try IPAddressRange(cidr)
        let route = RouteSpec(destination: range.address, prefixLength: range.networkPrefixLength, interfaceName: "utun7")
        let data = try RouteMessageCodec.build(operation, route: route, index: 7, sequence: 10, pid: 20)
        let reply = try RouteMessageCodec.parse(data)
        #expect(reply.type == operation.rawValue); #expect(reply.matches(route, index: 7))
        #expect(reply.hasOwnershipMark); #expect(reply.flags & 2 == 0)
        #expect(reply.addresses[1]?[1] == 18)
        #expect(RouteMessageCodec.isReply(reply, operation: operation, sequence: 10, pid: 20))
        #expect(!RouteMessageCodec.isReply(reply, operation: operation, sequence: 11, pid: 20))
        #expect(!RouteMessageCodec.isReply(reply, operation: operation, sequence: 10, pid: 21))
    }

    @Test
    func `malformed and truncated messages cannot authorise a route`() throws {
        let harness = try NetworkPortHarness()
        let good = try RouteMessageCodec.build(.get, route: harness.route, index: 7, sequence: 1, pid: 2)
        for length in 0 ..< good.count {
            #expect(throws: (any Error).self) { try RouteMessageCodec.parse(good.prefix(length)) }
        }
        let mutations: [(Int, UInt8)] = [(2, 4), (3, 255), (92, 255), (12, 0)]
        for (offset, value) in mutations {
            var invalid = good; invalid[offset] = value
            #expect(throws: (any Error).self) { try RouteMessageCodec.parse(invalid) }
        }
        var sequences = RouteSequence()
        let first = try sequences.next(), second = try sequences.next()
        #expect(first == 1); #expect(second == 2)
        var invalid = harness.route; invalid.prefixLength = 33
        #expect(throws: (any Error).self) { try RouteMessageCodec.build(.add, route: invalid, index: 7, sequence: 1, pid: 2) }
    }

    @Test
    func `one hundred install remove cycles are idempotent and journal guarded`() async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        for _ in 0 ..< 100 {
            try await table.install([harness.route], generation: harness.generation)
            try await table.install([harness.route], generation: harness.generation)
            #expect(await table.ownedRoutes() == [harness.route])
            try await table.removeRoutes(of: harness.generation)
            try await table.removeRoutes(of: harness.generation)
            #expect(await table.ownedRoutes().isEmpty)
        }
        #expect(await kernel.requests.filter { $0.type == 1 }.count == 100)
        #expect(await kernel.requests.filter { $0.type == 2 }.count == 100)
    }

    @Test(arguments: 0 ..< 8)
    func `delete requires journal mark and exact creation identity`(mask: Int) async throws {
        let journalled = mask & 1 != 0, tagged = mask & 2 != 0, identityMatches = mask & 4 != 0
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(identityMatches ? harness.identity : TunnelIdentity.held("utun7", index: 7))
        var record = try Array(RouteMessageCodec.build(.add, route: harness.route, index: 7, sequence: 1, pid: 999))
        RouteMessageCodec.put(tagged ? 0x4801 : 0x801, at: 8, into: &record)
        try await kernel.seed(RouteMessageCodec.parse(Data(record)))
        if !journalled {
            try harness.journal.mutate(generation: harness.generation) { $0.resources = [] }
        }
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        try await table.removeRoutes(of: harness.generation)
        #expect(await kernel.requests.contains { $0.type == 2 } == (journalled && tagged && identityMatches))
    }

    @Test
    func `foreign route and reused index survive reconciliation while missing route is restored`() async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        try await table.reconcile(harness.resources)
        await kernel.eraseAll()
        try await table.reconcile(harness.resources)
        #expect(await table.ownedRoutes() == [harness.route])
        let foreign = try RouteMessageCodec.build(.add, route: harness.route, index: 8, sequence: 2, pid: 999)
        try await kernel.seed(RouteMessageCodec.parse(foreign))
        await #expect(throws: DaemonFailure.portNotOwned) { try await table.reconcile(harness.resources) }
        try await table.removeRoutes(of: harness.generation)
        #expect(await kernel.requests.filter { $0.type == 2 }.isEmpty)
    }

    @Test
    func `get and change require the same ownership proof as deletion`() async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        let probe = LegacyRouteProbe(table: table, journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        #expect(try await probe.get(harness.route, generation: harness.generation) == nil)
        await #expect(throws: DaemonFailure.portNotOwned) { try await probe.change(harness.route, generation: harness.generation) }
        try await table.install([harness.route], generation: harness.generation)
        try await probe.change(harness.route, generation: harness.generation)
        #expect(try await probe.get(harness.route, generation: harness.generation)?.route == harness.route)
        #expect(await kernel.requests.filter { $0.type == 3 }.count == 1)
        await kernel.setIdentity(TunnelIdentity.held("utun7", index: 7))
        await #expect(throws: DaemonFailure.portNotOwned) { try await probe.change(harness.route, generation: harness.generation) }
    }

    @Test(arguments: [UInt16(7), UInt16(8)])
    func `fallback GET verifies the returned interface index`(returnedIndex: UInt16) async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let foreign = try RouteMessageCodec.build(.add, route: harness.route, index: UInt32(returnedIndex), sequence: 1, pid: 999)
        try await kernel.seed(RouteMessageCodec.parse(foreign))
        let table = RouteTable(journal: harness.journal, kernel: ExchangeOnlyRoutes(base: kernel), identities: kernel, pid: 123)
        #expect(try await table.observed(harness.resources).count == (returnedIndex == 7 ? 1 : 0))
        #expect(await kernel.dumpCount == 0)
        #expect(await kernel.requests.count == 1)
    }
}

private struct ExchangeOnlyRoutes: RouteMessageExchanging {
    let base: FakeRouteKernel
    func exchange(_ request: Data) async throws -> RouteMessage {
        try await base.exchange(request)
    }
}
