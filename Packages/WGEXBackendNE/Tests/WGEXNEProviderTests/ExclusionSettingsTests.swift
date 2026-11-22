// SPDX-License-Identifier: MIT

import Foundation
import Network
import Synchronization
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

/// DEC-087: literal and resolved exclusions become NE excluded routes per family.
private struct ExclusionSettingsTests {
    @Test(arguments: [ProfilePlatform.iOS, .tvOS])
    func `literal and resolved exclusions become excluded routes and tunnel addresses never do`(platform: ProfilePlatform) throws {
        var profile = try GoldenFixture.profile()
        profile.protection.tv.allowLAN = false
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "2001:db8:5::/48", "example.com"])
        let resolved = try ["203.0.113.7", "2001:db8:9::1", "10.8.0.1", "fd00::9"].map(IPAddressRange.init)
        let settings = try NESettingsGenerator.generate(profile, platform: platform, resolvedExclusions: resolved)
        #expect(settings.ipv4?.excludedRoutes.map(\.stringRepresentation) == ["198.51.100.0/24", "203.0.113.7/32"])
        #expect(settings.ipv6?.excludedRoutes.map(\.stringRepresentation) == ["2001:db8:5::/48", "2001:db8:9::1/128"])
        #expect(settings.ipv4?.includedRoutes.map(\.stringRepresentation) == ["0.0.0.0/0"])
    }

    @Test
    func `tvOS keeps its LAN exclusions first and adds the tunnel's after them`() throws {
        var profile = try GoldenFixture.profile()
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "10.0.0.0/8"])
        let settings = try NESettingsGenerator.generate(profile, platform: .tvOS)
        let v4 = settings.ipv4?.excludedRoutes.map(\.stringRepresentation) ?? []
        #expect(v4.prefix(4) == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"])
        #expect(v4.filter { $0 == "10.0.0.0/8" }.count == 1)
        #expect(v4.contains("198.51.100.0/24"))
    }

    @Test
    func `port exclusions add no NE setting and the provider reports them as not supported`() async throws {
        var profile = try GoldenFixture.profile()
        let plain = try NESettingsGenerator.generate(profile, platform: .iOS)
        profile.exclusions = try TunnelExclusions(entries: ["1911", "6881-6889/udp"])
        #expect(try NESettingsGenerator.generate(profile, platform: .iOS) == plain)
        let clock = TestClock()
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: FakeProviderSystem(clock: clock), profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(),
            resolver: FakeResolver(), clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        try await controller.startTunnel(profileID: profile.id)
        let status = await controller.status
        #expect(status.unsupportedExclusionPorts == ["1911", "6881-6889/udp"])
        #expect(UserStrings.exclusionPortsUnsupported(status.unsupportedExclusionPorts)
            == "Port exclusions 1911, 6881-6889/udp are not supported on this device.")
        await controller.stopTunnel(reason: 17)
    }

    /// M08-R01 F2: Force all traffic on iPhone and iPad makes NE ignore excluded routes, so none are emitted there; the
    /// flag does not reach Apple TV, which keeps them.
    @Test
    func `force all traffic emits no excluded routes on iPhone and iPad and leaves Apple TV unchanged`() throws {
        var profile = try GoldenFixture.profile()
        profile.protection.tv.allowLAN = false
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "2001:db8:5::/48", "example.com"])
        let resolved = try [IPAddressRange("203.0.113.7")]
        let applied = try NESettingsGenerator.generate(profile, platform: .iOS, resolvedExclusions: resolved)
        #expect(applied.ipv4?.excludedRoutes.isEmpty == false)
        profile.protection.ios.includeAllNetworks = true
        #expect(!NESettingsGenerator.appliesExclusions(profile, platform: .iOS))
        let forced = try NESettingsGenerator.generate(profile, platform: .iOS, resolvedExclusions: resolved)
        #expect(forced.ipv4?.excludedRoutes.isEmpty == true)
        #expect(forced.ipv6?.excludedRoutes.isEmpty == true)
        #expect(forced.ipv4?.includedRoutes == applied.ipv4?.includedRoutes)
        #expect(NESettingsGenerator.appliesExclusions(profile, platform: .tvOS))
        #expect(try NESettingsGenerator.generate(profile, platform: .tvOS, resolvedExclusions: resolved).ipv4?.excludedRoutes
            .map(\.stringRepresentation) == ["198.51.100.0/24", "203.0.113.7/32"])
    }

    /// M08-R01 F2: the tunnel still starts with Force all traffic on; nothing is looked up, the address and name entries
    /// are reported with the status note, and ports keep their own note.
    @Test
    func `with force all traffic the provider starts, applies no exclusions and reports them`() async throws {
        var profile = try GoldenFixture.profile()
        profile.protection.ios.includeAllNetworks = true
        profile.exclusions = try TunnelExclusions(entries: ["198.51.100.0/24", "example.com", "1911"])
        let clock = TestClock()
        let system = FakeProviderSystem(clock: clock)
        let resolver = ExclusionCountingResolver()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(),
            resolver: resolver, clock: clock, platform: .iOS, engineFactory: { try RecordingEngineFactory().make($0) },
        )
        try await controller.startTunnel(profileID: profile.id)
        let status = await controller.status
        guard case .active = status.phase else {
            Issue.record("the tunnel did not start: \(status.phase)"); return
        }
        #expect(status.forceAllIgnoredExclusions == ["198.51.100.0/24", "example.com"])
        #expect(status.unsupportedExclusionPorts == ["1911"])
        #expect(status.unresolvedExclusions.isEmpty)
        #expect(await resolver.exclusionNames.allSatisfy(\.isEmpty))
        let applied = try #require(await system.settings.compactMap(\.self).last)
        #expect(applied.ipv4?.excludedRoutes.isEmpty == true && applied.ipv6?.excludedRoutes.isEmpty == true)
        #expect(UserStrings.exclusionsForceAllTraffic == "Exclusions are not applied while Force all traffic is on.")
        let decoded = try JSONDecoder().decode(TunnelStatus.self, from: JSONEncoder().encode(status))
        #expect(decoded.forceAllIgnoredExclusions == status.forceAllIgnoredExclusions)
        await controller.stopTunnel(reason: 17)
    }

    @Test
    func `without exclusions the settings are unchanged`() throws {
        let profile = try GoldenFixture.profile()
        #expect(try NESettingsGenerator.generate(profile, platform: .iOS) ==
            NESettingsGenerator.generate(profile, platform: .iOS, resolvedExclusions: []))
        #expect(try NESettingsGenerator.generate(profile, platform: .iOS).ipv4?.excludedRoutes.isEmpty == true)
    }
}

/// Records the names each exclusion lookup was asked for.
private actor ExclusionCountingResolver: ProviderEndpointResolving {
    private(set) var exclusionNames: [[String]] = []
    func resolve(_ profile: TunnelProfile, interfaceIndex _: UInt32?) -> [PublicKey: Endpoint] {
        Dictionary(uniqueKeysWithValues: profile.peers.compactMap { peer in peer.endpoint.map { (peer.publicKey, $0) } })
    }

    func resolveExclusions(_ names: [String], interfaceIndex _: UInt32?) -> [String: [IPAddressRange]] {
        exclusionNames.append(names)
        return [:]
    }
}

/// M08-R01 F3: the NE exclusion lookups, through the lookup seam only; the host resolver is never used.
@Suite(.timeLimit(.minutes(1)))
private struct ExclusionLookupTests {
    @Test(arguments: [UInt32?.some(7), nil])
    func `each lookup is scoped to the physical interface with the tunnel prohibited`(index: UInt32?) async throws {
        let scopes = Mutex<[ExclusionLookupScope]>([])
        let many = try (1 ... 10).map { try IPAddressRange("192.0.2.\($0)") }
        let resolver = PhysicalEndpointResolver(lookup: { _, _ in [] }, exclusionLookup: { name, scope in
            scopes.withLock { $0.append(scope) }
            guard name == "a.example.test" else { throw TunnelError.backendUnavailable }
            return many
        }, clock: TestClock())
        let found = await resolver.resolveExclusions(["a.example.test", "b.example.test"], interfaceIndex: index)
        let expected = ExclusionLookupScope(requiredInterfaceIndex: index, prohibitedInterfaceTypes: [.other, .loopback])
        #expect(scopes.withLock { $0 } == [expected, expected])
        #expect(found["a.example.test"] == Array(many.prefix(TunnelExclusions.maximumAddressesPerHost)))
        #expect(found["b.example.test"] == [])
    }

    @Test(arguments: [false, true])
    func `no lookup starts after the deadline or a cancellation`(cancel: Bool) async throws {
        let gate = LookupGate()
        let clock = TestClock()
        let resolver = PhysicalEndpointResolver(lookup: { _, _ in [] }, exclusionLookup: { name, _ in
            await gate.lookup(name)
        }, clock: clock)
        let task = Task { await resolver.resolveExclusions(["a.example.test", "b.example.test"], interfaceIndex: 4) }
        await eventually { gate.started == ["a.example.test"] && clock.sleeperCount > 0 }
        if cancel {
            task.cancel()
        } else {
            clock.advance(10)
        }
        #expect(await task.value.isEmpty)
        // The first lookup ignores cancellation and answers late; the next name must still never start.
        try gate.release([IPAddressRange("192.0.2.1")])
        try await Task.sleep(for: .milliseconds(200))
        #expect(gate.started == ["a.example.test"])
    }
}

/// Holds each lookup until released, ignoring cancellation, like a system call that answers late.
private final class LookupGate: Sendable {
    private struct State {
        var started: [String] = []
        var waiting: [CheckedContinuation<[IPAddressRange], Never>] = []
    }

    private let state = Mutex(State())
    var started: [String] {
        state.withLock { $0.started }
    }

    func lookup(_ name: String) async -> [IPAddressRange] {
        await withCheckedContinuation { continuation in
            state.withLock { $0.started.append(name); $0.waiting.append(continuation) }
        }
    }

    func release(_ answers: [IPAddressRange]) {
        let waiting = state.withLock { state in
            defer { state.waiting = [] }
            return state.waiting
        }
        for continuation in waiting {
            continuation.resume(returning: answers)
        }
    }
}
