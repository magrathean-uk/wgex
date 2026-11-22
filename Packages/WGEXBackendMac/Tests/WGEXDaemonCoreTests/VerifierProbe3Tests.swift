// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting

/// Whether this test target is a debug build: its own condition, never the production flag under test. A broken
/// `RouteMatchCost.isCounting` then fails the first test below instead of skipping the suite (M1-33 N2).
private let testTargetIsDebug: Bool = {
    #if DEBUG
        true
    #else
        false
    #endif
}()

/// The route-key counter counts in debug builds only (M1-31), which is every configuration these tests run in.
@Suite(.timeLimit(.minutes(2)), .enabled(if: testTargetIsDebug, "the route-key counter counts in debug builds only"))
private struct VerifierProbe3Tests {
    @Test
    func `the route-key counter counts in a debug build`() {
        #expect(
            RouteMatchCost.isCounting,
            "RouteMatchCost.isCounting is false in a debug build: the cost tests below would prove nothing",
        )
    }

    /// Over the linear match (hashes and comparisons included) by more than twice, and 1/16 of a quadratic one.
    private static let linearOperationBound = 30 * 1000

    @Test
    func `probe dump based route verification cost with one thousand routes`() async throws {
        let harness = try NetworkPortHarness(), kernel = FakeRouteKernel()
        await kernel.setIdentity(harness.identity)
        let table = RouteTable(journal: harness.journal, kernel: kernel, identities: kernel, pid: 123)
        let routes = (0 ..< 1000).map { RouteSpec(destination: "10.\($0 / 256).\($0 % 256).0", prefixLength: 24, interfaceName: "utun7") }
        try harness.journal.mutate(generation: harness.generation) { $0.resources[0].routes = routes }
        try await table.install(routes, generation: harness.generation)
        let resource = try #require(harness.journal.snapshot().resources.first)
        let dumpsBefore = await kernel.dumpCount, requestsBefore = await kernel.requests.count
        let cost = RouteMatchCost.Counter()
        let observed = try await RouteMatchCost.$counter.withValue(cost) { try await table.observed(resource) }
        #expect(observed.count == 1000)
        // The cost property, as counts that no host load can move: one bulk snapshot of the kernel table for all 1,000
        // routes and no per-route RTM_GET, and a match that does a bounded number of key operations per route and per dump
        // entry. Every route-key operation is counted: a construction (an index entry, a lookup, a `matches` comparison),
        // a hash, and an equality comparison. The linear match makes about 12,000 to 13,000 operations (it varies with the
        // process's hash seed, through probe collisions); a quadratic one is far over the bound whether it builds a key per comparison
        // (about 500,000 constructions) or compares the
        // stored keys without building any (about 500,000 comparisons, M1-29 NF3). This replaces the 50 ms bound, which
        // proved the same thing and tripped under host load 105-132 (M1-25 fix pass 1, B N8) (M1-29 R4, M1-30 NF3).
        #expect(await kernel.dumpCount - dumpsBefore == 1, "observed() took more than one kernel dump")
        #expect(await kernel.requests.count == requestsBefore, "observed() issued per-route kernel requests")
        #expect(cost.operations <= Self.linearOperationBound, "observed() with 1,000 routes made \(cost.operations) route-key operations")
        #expect(cost.operations >= 1000, "the cost counter did not see the match (\(cost.operations) operations)")
    }

    /// The counter itself: a comparison or a hash of keys that already exist is an operation, so a scan that builds no
    /// key still shows (M1-30 NF3). Nothing is counted outside a task that installed a counter.
    @Test
    func `route key comparisons and hashes are counted without any key being built`() throws {
        let routes = (0 ..< 100).map { RouteSpec(destination: "10.0.\($0).0", prefixLength: 24, interfaceName: "utun7") }
        let keys = try routes.map { try #require(RouteLookupKey(route: $0, index: 7)) }
        let unset = keys[0] == keys[1]
        #expect(!unset)
        let cost = RouteMatchCost.Counter()
        RouteMatchCost.$counter.withValue(cost) {
            var matches = 0
            for key in keys where keys.first(where: { $0 == key }) != nil {
                matches += 1
            }
            #expect(matches == 100)
        }
        // keys.first(where:) compares each key with every key before its own: 1 + 2 + ... + 100.
        #expect(cost.operations == 5050, "comparisons were not counted (\(cost.operations) operations)")
        let hashing = RouteMatchCost.Counter()
        RouteMatchCost.$counter.withValue(hashing) {
            #expect(Set(keys).count == 100)
        }
        #expect(hashing.operations >= 100, "hashes were not counted (\(hashing.operations) operations)")
    }
}
