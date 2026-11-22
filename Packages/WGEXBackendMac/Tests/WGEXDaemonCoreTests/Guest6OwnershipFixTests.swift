// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// M1-17 fix pass 1: recovery teardown after en0 moved (F2), the adoption conditions (F3), Lab adoption and refusal lines
/// (F4) and our own leaked canary on the same scope (N7), on the XNU route model.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6OwnershipFixTests {
    @Test(arguments: [false, true])
    func `F2 startup reconciliation removes the canary after en0 moved and keeps the record while it stays`(
        _ deleteFails: Bool,
    ) async throws {
        let stack = try await ModelStack()
        _ = try await stack.start()
        #expect(stack.model.canaries.count == 1)
        try await stack.journal.mutate(generation: stack.controller.currentGeneration) { $0.intent = nil }
        await stack.controller.cancelBackgroundWork()
        // The utun died with the daemon; en0 had a link or flag change before launchd restarted it.
        stack.model.attach("utun9", index: 9, seconds: 5000)
        stack.model.touch("en0")
        if deleteFails {
            stack.model.failDeletes()
        }
        let replacement = try stack.replacement()
        if deleteFails {
            await #expect(throws: (any Error).self) { try await replacement.reconcileAtStartup() }
        } else {
            try await replacement.reconcileAtStartup()
        }
        let document = try DaemonJournal(directory: StateDirectory(root: stack.host.root)).snapshot()
        #expect(stack.model.canaries.count == (deleteFails ? 1 : 0))
        #expect(document.resources.isEmpty == !deleteFails)
        await replacement.cancelBackgroundWork()
    }

    @Test
    func `F3 adoption refuses when the journal already holds another identity`() async throws {
        let stack = try await ModelStack(drift: .sameIndex)
        _ = try await stack.start()
        let recorded = try #require(stack.journal.snapshot().resources.first?.identity)
        // M1-18: a moved stamp is the same identity; another identity is another utun9 (a new descriptor).
        let other = stack.model.attach("utun9", index: 9)
        await #expect(throws: DaemonFailure.portNotOwned) {
            try await stack.controller.configureChangedUnderlay(stack.host.profile, identity: other)
        }
        #expect(stack.journal.snapshot().resources.first?.identity == recorded)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `F3 adoption refuses when the engine reports another interface name`() async throws {
        let stack = try await ModelStack(drift: .sameIndex, engineName: "utun-other")
        await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        #expect(!stack.model.requests.contains { $0.type == RouteOperation.add.rawValue })
        #expect(await stack.controller.status.protection == .blocked)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `F3 a path change without an engine for the generation never adopts`() async throws {
        let stack = try await ModelStack(drift: .sameIndex)
        let generation = await stack.controller.currentGeneration
        let identity = stack.model.attach("utun9", index: 9)
        var resource = GenerationResources(generation: generation); resource.identity = identity
        try stack.journal.mutate(generation: generation) { $0.resources = [resource] }
        await #expect(throws: DaemonFailure.portNotOwned) {
            try await stack.controller.configureChangedUnderlay(stack.host.profile, identity: identity)
        }
        #expect(stack.journal.snapshot().resources.first?.identity == identity)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `N7 our own leaked canary on the same scope is replaced whatever its router`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1004807, gateway: "192.0.2.253")
        _ = try journalCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        try await table.install(h.resources.routes, generation: h.generation)
        #expect(model.canaries.map(\.gatewayAddress) == ["192.0.2.254"])
        #expect(model.canaries.map(\.flags) == [0x1004807])
        #expect(model.requests.contains { $0.type == RouteOperation.delete.rawValue && $0.index == 4 })
        try await table.removeRoutes(of: h.generation)
        #expect(model.owned.isEmpty)
    }

    @Test
    func `N7 a marked route of another shape on the canary scope stays foreign`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
        try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1004805, gateway: "192.0.2.253")
        _ = try journalCanary(h, model: model, router: "192.0.2.254")
        let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
        await #expect(throws: DaemonFailure.portNotOwned) { try await table.install(h.resources.routes, generation: h.generation) }
        #expect(model.canaries.map(\.flags) == [0x1004805])
        #expect(!model.requests.contains { $0.type == RouteOperation.delete.rawValue && $0.index == 4 })
    }

    #if WGEX_LAB_BUILD
        @Test
        func `F4 Lab lines tell adoption, replacement and an EEXIST refusal apart`() async throws {
            let lines = Mutex<[String]>([])
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                for (flags, gateway) in [(UInt32(0x1004807), "192.0.2.254"), (0x1004807, "192.0.2.253")] {
                    let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
                    model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
                    try model.seed("192.0.2.1", scope: 4, index: 4, flags: flags, gateway: gateway)
                    _ = try journalCanary(h, model: model, router: "192.0.2.254")
                    let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
                    try await table.install(h.resources.routes, generation: h.generation)
                    try await table.install(h.resources.routes, generation: h.generation)
                }
                let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
                model.attach("en0", index: 4); model.attach(h.identity.name, index: 7)
                try model.seed("192.0.2.1", scope: 4, index: 4, flags: 0x1000807, gateway: "192.0.2.254", hidden: true)
                _ = try journalCanary(h, model: model, router: "192.0.2.254")
                let table = RouteTable(journal: h.journal, kernel: DarwinRouteKernel(model: model), identities: model, pid: 123)
                await #expect(throws: DaemonFailure.portNotOwned) {
                    try await table.install(h.resources.routes, generation: h.generation)
                }
            }
            #expect(lines.withLock { $0 } == [
                "ownership: canary adopted",
                "ownership: canary replaced",
                "ownership: foreign route",
            ])
        }

        @Test
        func `ownership labels cover every event`() {
            let labels = DaemonDiagnostics.OwnershipEvent.allCases.compactMap { DaemonDiagnostics.ownershipLabels[$0] }
            #expect(labels.count == DaemonDiagnostics.OwnershipEvent.allCases.count)
            #expect(Set(labels).count == labels.count)
            #expect(labels.allSatisfy { $0.range(of: "^[a-z ]{1,40}$", options: .regularExpression) != nil })
        }
    #endif

    private func journalCanary(_ h: NetworkPortHarness, model: DarwinRouteKernelModel, router: String) throws -> OwnedCanaryRoute {
        let physical = try #require(model.identity(named: "en0"))
        let canary = try OwnedCanaryRoute(identity: physical, router: router)
        try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = model.identity(named: "utun7") }
        try h.journal.mutate(generation: h.generation) { $0.resources[0].canaryRoute = canary; $0.resources[0].routes.append(canary.route) }
        return canary
    }
}
