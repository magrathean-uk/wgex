// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// M1-18 fix pass 1 (verifier F2): when recovery no longer recognises en0 under the underlay fence, the journalled canary
/// is still torn down by NetworkRealityInspector.removeOwned's canary-only branch (RouteTable's teardown fence: name and
/// index plus the route's mark, scope and router) and the record is retired. The two M1-18 cases: en0 reports another
/// link-layer address, and a canary recorded before M1-18 (stamp, no link address) after the upgrade.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6CanaryRecoveryTests {
    enum Unrecognised: CaseIterable, Sendable { case linkAddressChanged, preM118Record }

    /// The canary as a pre-M1-18 daemon journalled it: its en0 identity carries the stamp and no link-layer address.
    private static func legacyCanary(router: String) throws -> OwnedCanaryRoute {
        try JSONDecoder().decode(OwnedCanaryRoute.self, from: Data("""
        {"identity":{"name":"en0","interfaceIndex":4,"creationID":"E8030000-0000-0000-0000-000000000000"},"router":"\(router)"}
        """.utf8))
    }

    @Test(arguments: Unrecognised.allCases)
    func `M1-18 crash replay removes the journalled canary when en0 is no longer recognised`(_ case: Unrecognised) async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        let physical = try #require(model.identity(named: "en0"))
        let canary = try OwnedCanaryRoute(identity: physical, router: "192.0.2.254")
        try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = model.identity(named: "utun7") }
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = canary; $0.resources[0].routes.append(canary.route) }
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.count == 1)
        // The daemon died with its utun; the restarted daemon holds no descriptor for it.
        model.attach(h.identity.name, index: 7, seconds: 5000)
        switch `case` {
        case .linkAddressChanged: model.setLinkAddress("en0", "02:00:5e:00:00:99")
        case .preM118Record:
            let legacy = try Self.legacyCanary(router: canary.router)
            #expect(legacy.identity.linkAddress == nil && legacy.route == canary.route)
            try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = legacy }
        }
        let restarted = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 456)
        let inspector = NetworkRealityInspector(routes: restarted, dns: AcceptingDNS(), identities: model)
        let owned = try await DaemonReconciliation.ownedResources(h.resources, observed: inspector.inspect(h.resources))
        #expect(owned.canaryRoute == nil)
        #expect(owned.routes.isEmpty)
        try await inspector.removeOwned(owned)
        #expect(model.canaries.isEmpty)
        // The utun route of the vanished interface is not this daemon's to touch.
        #expect(model.owned.count == 1)
    }

    @Test(arguments: Unrecognised.allCases)
    func `M1-18 startup reconciliation removes the canary and retires the record when en0 is no longer recognised`(
        _ case: Unrecognised,
    ) async throws {
        let stack = try await ModelStack()
        _ = try await stack.start()
        #expect(stack.model.canaries.count == 1)
        let generation = await stack.controller.currentGeneration
        try stack.journal.mutate(generation: generation) { $0.intent = nil }
        await stack.controller.cancelBackgroundWork()
        stack.model.attach("utun9", index: 9, seconds: 5000)
        switch `case` {
        case .linkAddressChanged: stack.model.setLinkAddress("en0", "02:00:5e:00:00:99")
        case .preM118Record:
            let router = try #require(stack.journal.snapshot().resources.first?.canaryRoute?.router)
            let legacy = try Self.legacyCanary(router: router)
            try stack.journal.mutate(generation: generation) { $0.resources[0].canaryRoute = legacy }
        }
        let replacement = try stack.replacement()
        try await replacement.reconcileAtStartup()
        #expect(stack.model.canaries.isEmpty)
        #expect(try DaemonJournal(directory: StateDirectory(root: stack.host.root)).snapshot().resources.isEmpty)
        await replacement.cancelBackgroundWork()
    }
}
