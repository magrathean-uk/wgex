// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// M1-18: the ownership fences without the kernel's last-change stamp. The utun is fenced by name, index, this process's
/// descriptor and the assigned addresses; en0 and the canary by name, index and link-layer address.
@Suite(.timeLimit(.minutes(1)))
private struct Guest6FenceTests {
    enum Fault: CaseIterable, Sendable {
        case utunIndex, utunDescriptorClosed, utunAddressGone, en0Index, en0LinkAddress
    }

    @Test(arguments: Fault.allCases)
    func `M1-18 a real ownership change refuses on the next verification and keeps the policy loaded`(_ fault: Fault) async throws {
        let stack = try await ModelStack()
        let generation = try await stack.start()
        let peer = try #require(stack.host.profile.peers.first?.publicKey)
        await stack.controller.consume(.handshakeCompleted(peer: peer, at: stack.host.clock.wallNow), generation: generation)
        let address = try #require(stack.host.profile.interface.addresses.first)
        // The stamps move as in the guest; only the fault is an ownership change.
        stack.model.touch("en0"); stack.model.touch("utun9")
        switch fault {
        case .utunIndex: stack.model.touch("utun9", index: 10)
        case .utunDescriptorClosed: stack.model.closeDescriptor("utun9")
        case .utunAddressGone: stack.model.removeAddress(address, from: "utun9")
        case .en0Index: stack.model.touch("en0", index: 5)
        case .en0LinkAddress: stack.model.setLinkAddress("en0", "02:00:5e:00:00:99")
        }
        stack.host.clock.advance(.seconds(5))
        await #expect(throws: (any Error).self) { try await stack.controller.tick() }
        let status = await stack.controller.status
        #expect(status.protection == .blocked)
        #expect(status.phase != .active(generation))
        #expect(await stack.host.ports.policy != .disconnected)
        #expect(stack.journal.snapshot().pfPolicy != .disconnected)
        await stack.controller.cancelBackgroundWork()
    }

    @Test(arguments: [ModelStack.Drift.newIndex(10), .descriptorClosed, .addressGone])
    func `M1-18 a utun change during the start refuses before any route is added`(_ drift: ModelStack.Drift) async throws {
        let stack = try await ModelStack(drift: drift)
        await #expect(throws: DaemonFailure.portNotOwned) { try await stack.start() }
        #expect(!stack.model.requests.contains { $0.type == RouteOperation.add.rawValue })
        #expect(await stack.controller.status.protection == .blocked)
        #expect(await stack.host.ports.policy != .disconnected)
        await stack.controller.cancelBackgroundWork()
    }

    @Test
    func `M1-18 the journal keeps descriptor and link address, and a pre-M1-18 record is never the daemon's utun`() throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        let physical = model.attach("en0", index: 4), tunnel = model.attach("utun7", index: 7, generation: h.generation)
        let canary = try OwnedCanaryRoute(identity: physical, router: "192.0.2.254")
        try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = tunnel; $0.resources[0].canaryRoute = canary }
        let reopened = try DaemonJournal(directory: StateDirectory(root: h.root)).snapshot().resources[0]
        #expect(reopened.identity == tunnel)
        #expect(reopened.identity?.descriptor == TunnelDescriptor(fd: tunnel.descriptor?.fd ?? -1, generation: h.generation))
        #expect(reopened.canaryRoute?.identity.linkAddress == "02:00:5e:00:00:04")
        #expect(reopened.canaryRoute?.identity.descriptor == nil)
        // A record written before M1-18 carries the stamp, which is ignored; with no descriptor the fence refuses it.
        let legacy = try JSONDecoder().decode(TunnelIdentity.self, from: Data("""
        {"name":"utun7","interfaceIndex":7,"creationID":"E8030000-0000-0000-0000-000000000000"}
        """.utf8))
        #expect(legacy == TunnelIdentity(name: "utun7", interfaceIndex: 7))
        let unheld = TunnelIdentity(name: "utun7", interfaceIndex: 7)
        #expect(InterfaceFence.tunnel(addresses: []).breach(recorded: legacy, current: unheld, present: []) == .descriptor)
        var expected = GenerationResources(generation: h.generation); expected.identity = legacy
        let snapshot = DaemonRealitySnapshot(identity: unheld, routes: [], dnsKey: nil, dns: nil)
        #expect(DaemonReconciliation.ownedResources(expected, observed: snapshot).identity == nil)
    }

    @Test
    func `M1-18 fence rules ignore nothing but the stamp`() throws {
        let descriptor = TunnelDescriptor(fd: 9, generation: .initial)
        let utun = TunnelIdentity(name: "utun4", interfaceIndex: 12, descriptor: descriptor)
        let address = try IPAddressRange("10.77.0.2/24")
        let tunnel = InterfaceFence.tunnel(addresses: [address])
        let present = try [IPAddressRange("10.77.0.2/32")]
        #expect(tunnel.breach(recorded: utun, current: utun, present: present) == nil)
        #expect(tunnel.breach(recorded: utun, current: nil, present: present) == .absent)
        #expect(tunnel
            .breach(recorded: utun, current: .init(name: "utun4", interfaceIndex: 13, descriptor: descriptor), present: present) == .index)
        #expect(tunnel.breach(recorded: utun, current: .init(name: "utun4", interfaceIndex: 12), present: present) == .descriptor)
        let later = TunnelDescriptor(fd: 9, generation: Generation.initial.next())
        #expect(tunnel
            .breach(recorded: utun, current: .init(name: "utun4", interfaceIndex: 12, descriptor: later), present: present) == .descriptor)
        #expect(tunnel.breach(recorded: utun, current: utun, present: []) == .address)
        #expect(InterfaceFence.tunnel(addresses: []).breach(recorded: utun, current: utun, present: []) == nil)
        let en0 = TunnelIdentity(name: "en0", interfaceIndex: 6, linkAddress: "02:00:5e:00:00:06")
        #expect(InterfaceFence.underlay.breach(recorded: en0, current: en0, present: []) == nil)
        #expect(InterfaceFence.underlay.breach(
            recorded: en0,
            current: .init(name: "en0", interfaceIndex: 7, linkAddress: "02:00:5e:00:00:06"),
            present: [],
        ) == .index)
        #expect(InterfaceFence.underlay.breach(
            recorded: en0,
            current: .init(name: "en0", interfaceIndex: 6, linkAddress: "02:00:5e:00:00:07"),
            present: [],
        ) == .linkAddress)
    }

    @Test
    func `M1-18 the descriptor table reports only an open descriptor naming the utun, with the generation that recorded it`() {
        let names = Mutex<[Int32: String]>([3: "utun4", 4: "utun5"])
        let table = TunnelDescriptorTable(probe: TunnelDescriptorProbe(
            candidates: { names.withLock { Array($0.keys) } + [0, 1, 2] }, interfaceName: { fd in names.withLock { $0[fd] } },
        ))
        let first = Generation.initial, second = first.next()
        #expect(table.descriptor(named: "utun4") == nil)
        #expect(table.register(name: "utun9", generation: first) == nil)
        #expect(table.register(name: "utun4", generation: first) == TunnelDescriptor(fd: 3, generation: first))
        #expect(table.descriptor(named: "utun4") == TunnelDescriptor(fd: 3, generation: first))
        #expect(table.descriptor(named: "utun5") == nil)
        // The descriptor now reports another name: utun4 is no longer held.
        names.withLock { $0[3] = "utun6" }
        #expect(table.descriptor(named: "utun4") == nil)
        // Closed, then the number reused by a later generation's engine for the same unit name.
        names.withLock { $0[3] = nil }
        #expect(table.descriptor(named: "utun4") == nil)
        names.withLock { $0[3] = "utun4" }
        #expect(table.register(name: "utun4", generation: second) == TunnelDescriptor(fd: 3, generation: second))
        #expect(table.descriptor(named: "utun4") == TunnelDescriptor(fd: 3, generation: second))
    }

    @Test
    func `M1-18 the system probe reports no utun name for an ordinary or a closed descriptor`() throws {
        var pair: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
        defer { close(pair[1]) }
        let probe = TunnelDescriptorProbe.system
        #expect(probe.candidates().contains(pair[0]))
        #expect(probe.interfaceName(pair[0]) == nil)
        close(pair[0])
        #expect(probe.interfaceName(pair[0]) == nil)
        #expect(!probe.candidates().contains(pair[0]))
    }

    @Test(arguments: [false, true])
    func `M1-18 the factory records the engine's descriptor for the generation or refuses and shuts the engine down`(
        _ held: Bool,
    ) async throws {
        let model = DarwinRouteKernelModel(), trace = HostTrace()
        let table = TunnelDescriptorTable(probe: TunnelDescriptorProbe(
            candidates: { [12] }, interfaceName: { held && $0 == 12 ? "utun9" : nil },
        ))
        let reader = TableReader(model: model, table: table)
        model.attach("utun9", index: 9, held: false)
        let engine = HostEngine(trace: trace, interfaceName: "utun9")
        try await engine.up()
        let factory = SystemDaemonEngineFactory(descriptors: table, identities: reader, makeEngine: { _ in engine })
        let configuration = EngineConfiguration(tun: .createUTun(mtu: 1280), bindInterfaceIndexV4: 1, bindInterfaceIndexV6: 1)
        let generation = Generation.initial.next()
        if held {
            let created = try await factory.create(configuration: configuration, generation: generation)
            #expect(created.identity == TunnelIdentity(
                name: "utun9", interfaceIndex: 9, descriptor: TunnelDescriptor(fd: 12, generation: generation),
            ))
        } else {
            await #expect(throws: DaemonPortError.notOwned) {
                try await factory.create(configuration: configuration, generation: generation)
            }
            #expect(trace.calls.contains("engine.shutdown"))
        }
    }

    @Test
    func `M1-18 the device confirms its own utun after configure despite a moved stamp and refuses a lost address`() async throws {
        let h = try NetworkPortHarness(), model = DarwinRouteKernelModel()
        let recorded = model.attach("utun7", index: 7, generation: h.generation)
        let address = try IPAddressRange("10.77.0.2/24")
        try h.journal.mutate(generation: h.generation) { $0.resources[0].identity = recorded; $0.resources[0].addresses = [address] }
        model.assign([address], to: "utun7")
        let device = SystemTunnelDevice(identities: model, journal: h.journal)
        let engine = HostEngine(trace: HostTrace(), interfaceName: "utun7"), other = HostEngine(trace: HostTrace(), interfaceName: "utun8")
        try await engine.up(); try await other.up()
        model.touch("utun7")
        #expect(try await device.identity(afterConfiguring: recorded, engine: engine) == recorded)
        await #expect(throws: DaemonFailure.portNotOwned) { try await device.identity(afterConfiguring: recorded, engine: nil) }
        await #expect(throws: DaemonFailure.portNotOwned) {
            try await device.identity(afterConfiguring: recorded, engine: other)
        }
        model.removeAddress(address, from: "utun7")
        await #expect(throws: DaemonFailure.portNotOwned) { try await device.identity(afterConfiguring: recorded, engine: engine) }
    }

    #if WGEX_LAB_BUILD
        @Test
        func `M1-18 Lab lines name the fence check that refused and never a stamp`() async throws {
            let lines = Mutex<[String]>([])
            try await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                for fault in Fault.allCases {
                    let stack = try await ModelStack()
                    let generation = try await stack.start()
                    let peer = try #require(stack.host.profile.peers.first?.publicKey)
                    await stack.controller.consume(.handshakeCompleted(peer: peer, at: stack.host.clock.wallNow), generation: generation)
                    let address = try #require(stack.host.profile.interface.addresses.first)
                    stack.model.touch("en0"); stack.model.touch("utun9")
                    switch fault {
                    case .utunIndex: stack.model.touch("utun9", index: 10)
                    case .utunDescriptorClosed: stack.model.closeDescriptor("utun9")
                    case .utunAddressGone: stack.model.removeAddress(address, from: "utun9")
                    case .en0Index: stack.model.touch("en0", index: 5)
                    case .en0LinkAddress: stack.model.setLinkAddress("en0", "02:00:5e:00:00:99")
                    }
                    stack.host.clock.advance(.seconds(5))
                    await #expect(throws: (any Error).self) { try await stack.controller.tick() }
                    await stack.controller.cancelBackgroundWork()
                }
            }
            let ownership = lines.withLock { $0 }.filter { $0.hasPrefix("ownership: ") }
            #expect(ownership == [
                "ownership: tunnel identity drift", "ownership: interface utun9 index 9->10 check index",
                "ownership: tunnel identity drift", "ownership: interface utun9 index 9->9 check descriptor",
                "ownership: tunnel identity drift", "ownership: interface utun9 index 9->9 check address",
                "ownership: canary route missing", "ownership: canary identity drift", "ownership: interface en0 index 4->5 check index",
                "ownership: canary route missing", "ownership: canary identity drift",
                "ownership: interface en0 index 4->4 check link address",
            ])
            #expect(!lines.withLock { $0 }.contains { $0.contains("change ") })
        }

        @Test
        func `M1-18 fence check labels cover every check`() {
            let labels = InterfaceFence.Breach.allCases.compactMap { DaemonDiagnostics.breachLabels[$0] }
            #expect(labels.count == InterfaceFence.Breach.allCases.count)
            #expect(Set(labels).count == labels.count)
            #expect(labels.allSatisfy { $0.range(of: "^[a-z ]{1,20}$", options: .regularExpression) != nil })
        }

        @Test
        func `M1-18 the factory names a missing descriptor`() async throws {
            let lines = Mutex<[String]>([])
            let table = TunnelDescriptorTable(probe: TunnelDescriptorProbe(candidates: { [] }, interfaceName: { _ in nil }))
            let engine = HostEngine(trace: HostTrace(), interfaceName: "utun9")
            try await engine.up()
            let factory = SystemDaemonEngineFactory(descriptors: table, identities: DarwinRouteKernelModel(), makeEngine: { _ in engine })
            await DaemonDiagnostics.$publicLineObserver.withValue({ line in lines.withLock { $0.append(line) } }) {
                await #expect(throws: DaemonPortError.notOwned) {
                    try await factory.create(
                        configuration: EngineConfiguration(tun: .createUTun(mtu: 1280), bindInterfaceIndexV4: 1, bindInterfaceIndexV6: 1),
                        generation: .initial,
                    )
                }
            }
            #expect(lines.withLock { $0 } == ["ownership: tunnel descriptor missing"])
        }
    #endif
}

/// The model's interfaces with this process's descriptors read from a table, as SystemInterfaceIdentity reads them.
private struct TableReader: InterfaceIdentityReading {
    let model: DarwinRouteKernelModel
    let table: TunnelDescriptorTable
    func identity(named name: String) -> TunnelIdentity? {
        model.identity(named: name).map {
            TunnelIdentity(
                name: name,
                interfaceIndex: $0.interfaceIndex,
                descriptor: table.descriptor(named: name),
                linkAddress: $0.linkAddress,
            )
        }
    }

    func addresses(named name: String) -> [IPAddressRange] {
        model.addresses(named: name)
    }
}
