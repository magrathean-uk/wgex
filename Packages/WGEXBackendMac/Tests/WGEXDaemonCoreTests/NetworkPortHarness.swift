// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
@testable import WGEXDaemonCore

package final class NetworkPortHarness: Sendable {
    package let root: URL
    package let journal: DaemonJournal
    package let generation: Generation
    package let profileID = UUID()
    package let identity = TunnelIdentity.held("utun7", index: 7)
    package let route = RouteSpec(destination: "128.0.0.0", prefixLength: 1, interfaceName: "utun7")
    package let configuration = DNSConfiguration(servers: ["10.77.0.1", "fd77::1"], searchDomains: ["example.test"], matchDomains: [""])
    package init() throws {
        root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-network-" + UUID().uuidString)
        journal = try DaemonJournal(directory: StateDirectory(root: root))
        generation = try journal.allocate(intent: TunnelIntent(profileID: profileID, ownerUID: 501))
        var resources = GenerationResources(generation: generation)
        resources.identity = identity; resources.routes = [route]; resources.dns = configuration
        resources.dnsKey = DNSConfigurator.key(profileID: profileID)
        try journal.mutate(generation: generation) { $0.resources = [resources] }
    }

    deinit { try? FileManager.default.removeItem(at: root) }
    package var resources: GenerationResources {
        journal.snapshot().resources[0]
    }

    package static func fixture(_ path: String) throws -> String {
        guard let url = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else { throw HostTestError.injected }
        return try String(contentsOf: url.appendingPathComponent(path), encoding: .utf8)
    }
}

/// Descriptor numbers for fixture identities; each call is a distinct descriptor, as each kernel creation was.
private let fixtureDescriptors = Atomic<Int32>(2000)

package extension TunnelIdentity {
    /// A utun held by a fresh descriptor of this process (M1-18): two calls never match, like two kernel creations.
    static func held(_ name: String, index: UInt32, generation: Generation = .initial) -> TunnelIdentity {
        let fd = fixtureDescriptors.add(1, ordering: .relaxed).newValue
        return TunnelIdentity(name: name, interfaceIndex: index, descriptor: TunnelDescriptor(fd: fd, generation: generation))
    }
}
