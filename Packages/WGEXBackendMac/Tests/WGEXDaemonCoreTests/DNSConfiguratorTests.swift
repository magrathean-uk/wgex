// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct DNSConfiguratorTests {
    @Test
    func `synthetic default resolver is first and scoped resolvers do not compete`() throws {
        let harness = try NetworkPortHarness()
        let value = try SyntheticDNSValue(configuration: harness.configuration, searchOrder: 1)
        let text = try NetworkPortHarness.fixture("DNS/default.txt")
        let records = ScutilDNSParser.parse(text)
        #expect(records.count == 4); #expect(records.last?.scoped == true)
        #expect(ScutilDNSParser.verifies(value, in: text))
        #expect(!ScutilDNSParser.verifies(value, in: text.replacingOccurrences(of: "order    : 200000", with: "order    : 0")))
        #expect(!ScutilDNSParser.verifies(value, in: text.replacingOccurrences(of: "order    : 200000", with: "order    : 1")))
        #expect(!ScutilDNSParser.verifies(value, in: text.replacingOccurrences(of: "nameserver[0] : 10.77.0.1", with: "")))
        #expect(!ScutilDNSParser.verifies(value, in: text.replacingOccurrences(of: "order    : 1", with: "order    : invalid")))
        #expect(!ScutilDNSParser.verifies(value, in: ""))
    }

    @Test
    func `split domains use supplemental resolvers without a synthetic primary`() throws {
        let configuration = DNSConfiguration(servers: ["10.77.0.1"], searchDomains: [], matchDomains: ["corp.example.test"])
        let value = try SyntheticDNSValue(configuration: configuration, searchOrder: 1)
        #expect(try ScutilDNSParser.verifies(value, in: NetworkPortHarness.fixture("DNS/split.txt")))
        #expect(try !ScutilDNSParser.verifies(value, in: NetworkPortHarness.fixture("DNS/default.txt")))
        let all = try SyntheticDNSValue(
            configuration: DNSConfiguration(servers: ["10.77.0.1"], searchDomains: [], matchDomains: []),
            searchOrder: 1,
        )
        #expect(all.configuration.matchDomains == [""])
    }

    @Test
    func `one temporary key remove then add verify and stop removal`() async throws {
        let harness = try NetworkPortHarness(), session = try FakeDNSSession(listing: NetworkPortHarness.fixture("DNS/default.txt"))
        let dns = DNSConfigurator(journal: harness.journal, session: session)
        try await dns.apply(harness.configuration, generation: harness.generation)
        try await dns.verify(harness.resources)
        #expect(await dns.current() == harness.configuration)
        #expect(await session.values.count == 1)
        #expect(await session.operations == ["remove", "addTemporary"])
        var next = harness.configuration; next.searchDomains = ["new.example.test"]
        try harness.journal.mutate(generation: harness.generation) { $0.resources[0].dns = next }
        try await dns.apply(next, generation: harness.generation)
        #expect(await session.operations == ["remove", "addTemporary", "remove", "addTemporary"])
        try await dns.remove(generation: harness.generation)
        try await dns.remove(generation: harness.generation)
        #expect(await session.values.isEmpty)
    }

    @Test
    func `journal generation and key guards preserve administrator replacements`() async throws {
        let harness = try NetworkPortHarness(), session = FakeDNSSession()
        let dns = DNSConfigurator(journal: harness.journal, session: session)
        await #expect(throws: DaemonFailure.portNotOwned) { try await dns.apply(
            harness.configuration,
            generation: harness.generation.next(),
        )
        }
        try await dns.apply(harness.configuration, generation: harness.generation)
        let key = try #require(harness.resources.dnsKey)
        let foreign = try SyntheticDNSValue(
            configuration: DNSConfiguration(servers: ["203.0.113.53"], searchDomains: [], matchDomains: [""]),
            searchOrder: 2,
        )
        await session.addTemporary(key: key, value: foreign)
        try await dns.remove(generation: harness.generation)
        #expect(await session.read(key: key) == foreign)
        await #expect(throws: DaemonFailure.portNotOwned) { try await dns.apply(harness.configuration, generation: harness.generation) }
        await #expect(throws: (any Error).self) { try await dns.verify(harness.resources) }
        #expect(await session.read(key: key) == foreign)
    }

    @Test
    func `missing temporary key is recreated by reconciliation`() async throws {
        let harness = try NetworkPortHarness(), session = try FakeDNSSession(listing: NetworkPortHarness.fixture("DNS/default.txt"))
        let dns = DNSConfigurator(journal: harness.journal, session: session)
        try await dns.apply(harness.configuration, generation: harness.generation)
        try await session.remove(key: #require(harness.resources.dnsKey))
        await #expect(throws: (any Error).self) { try await dns.verify(harness.resources) }
        try await dns.apply(harness.configuration, generation: harness.generation)
        try await dns.verify(harness.resources)
    }
}
