// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

private struct RevisionRefreshTests {
    @Test func `reload can explicitly refresh the accepted revision`() async throws {
        let (service, dispatcher, transport, client) = clientFixture()
        var profile = TunnelProfile(id: service.id, name: "Initial")
        try await client.install(profile)
        let other = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        profile.name = "Other client"
        try await other.install(profile)
        #expect(try await client.refreshRevision(profile.id) == 2)
        profile.name = "Reviewed edit"
        try await client.install(profile)
        #expect(await transport.requests.filter {
            if case .profileRevision = $0 {
                true
            } else {
                false
            }
        }.count == 2)
        await client.disconnect(); await other.disconnect()
    }

    @Test(arguments: [DaemonError.disconnected, .tunnel(.timedOut)])
    func `unknown CAS outcomes discard the cached revision`(_ failure: DaemonError) async throws {
        let (service, _, transport, client) = clientFixture()
        var profile = TunnelProfile(id: service.id, name: "Initial")
        try await client.install(profile)
        await transport.loseNextCASReply(failure)
        profile.name = "Accepted but reply lost"
        await #expect(throws: TunnelError.self) { try await client.install(profile) }
        profile.name = "Later explicit save"
        try await client.install(profile)
        #expect(await transport.requests.filter {
            if case .profileRevision = $0 {
                true
            } else {
                false
            }
        }.count == 2)
        let revisions = await transport.requests.compactMap { request -> UInt64?? in
            if case let .installProfileCAS(_, revision) = request {
                return .some(revision)
            }
            return nil
        }
        #expect(revisions == [nil, 1, 2])
        await client.disconnect()
    }

    @Test func `known CAS refusal retains the revision without a fresh query`() async throws {
        let (service, _, transport, client) = clientFixture()
        var profile = TunnelProfile(id: service.id, name: "Initial")
        try await client.install(profile)
        await transport.override(.error(.busy))
        profile.name = "Explicit retry"
        await #expect(throws: TunnelError.busy) { try await client.install(profile) }
        await transport.override(nil)
        try await client.install(profile)
        #expect(await transport.requests.filter { $0 == .profileRevision(profile.id) }.count == 1)
        await client.disconnect()
    }

    @Test func `failed reload leaves conflict blocked without querying or replaying CAS`() async throws {
        let (service, dispatcher, transport, client) = clientFixture()
        var profile = TunnelProfile(id: service.id, name: "Initial")
        try await client.install(profile)
        let other = DaemonClient(transport: RecordingClientTransport(dispatcher), clientVersion: "1", clientBuild: 10)
        profile.name = "Winner"
        try await other.install(profile)
        profile.name = "Stale edit"
        await #expect(throws: TunnelError.revisionConflict) { try await client.install(profile) }
        await transport.override(.error(.disconnected))
        await #expect(throws: DaemonError.disconnected) { try await client.refreshRevision(profile.id) }
        await transport.override(nil)
        let requests = await transport.requests.count
        await #expect(throws: TunnelError.revisionConflict) { try await client.install(profile) }
        #expect(await transport.requests.count == requests)
        #expect(try await other.refreshRevision(profile.id) == 2)
        await client.disconnect(); await other.disconnect()
    }
}
