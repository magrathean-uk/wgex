// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXNEProvider

/// Records literal lookups and answers from a script; never touches the host resolver.
private final class LookupRecorder: Sendable {
    struct Query: Equatable {
        let host: String
        let port: UInt16
    }

    struct State {
        var queries: [Query] = []
        var onLookupQueue: [Bool] = []
    }

    private let state = Mutex(State())
    private let answer: @Sendable (String, UInt16) throws -> [Endpoint]
    init(_ answer: @escaping @Sendable (String, UInt16) throws -> [Endpoint]) {
        self.answer = answer
    }

    var queries: [Query] {
        state.withLock { $0.queries }
    }

    var onLookupQueue: [Bool] {
        state.withLock { $0.onLookupQueue }
    }

    func lookup(host: String, port: UInt16) throws -> [Endpoint] {
        state.withLock {
            $0.queries.append(Query(host: host, port: port))
            $0.onLookupQueue.append(DispatchQueue.getSpecific(key: PhysicalEndpointResolver.lookupQueueKey) == true)
        }
        return try answer(host, port)
    }
}

private func resolver(_ recorder: LookupRecorder, clock: TestClock = TestClock()) -> PhysicalEndpointResolver {
    PhysicalEndpointResolver(lookup: { try recorder.lookup(host: $0, port: $1) }, clock: clock)
}

private func profile(endpoint: String) throws -> TunnelProfile {
    var profile = try GoldenFixture.profile()
    profile.peers[0].endpoint = try Endpoint(endpoint)
    return profile
}

private func endpoint(_ host: String, _ port: UInt16 = 51820) throws -> Endpoint {
    try Endpoint(validatingHost: host, port: port)
}

private let nat64 = "64:ff9b::c000:201"

@Suite(.timeLimit(.minutes(1)))
private struct EndpointResolutionTests {
    @Test(arguments: [("192.0.2.1:51820", "192.0.2.1"), ("[2001:db8::7]:51820", "2001:db8::7")])
    func `an IP literal goes through the lookup and the synthesised address replaces it`(_ text: String, _ host: String) async throws {
        let recorder = LookupRecorder { _, port in
            try [Endpoint(validatingHost: "64:ff9b::c000:201", port: port), Endpoint(validatingHost: "192.0.2.1", port: port)]
        }
        let profile = try profile(endpoint: text)
        let resolved = try await resolver(recorder).resolve(profile, interfaceIndex: 7)
        #expect(recorder.queries == [.init(host: host, port: 51820)])
        #expect(try resolved == [profile.peers[0].publicKey: endpoint(nat64)])
    }

    @Test
    func `the first result wins and the port is kept`() async throws {
        let recorder = LookupRecorder { _, port in
            try [Endpoint(validatingHost: "2001:db8::1", port: port), Endpoint(validatingHost: "198.51.100.9", port: port)]
        }
        let profile = try profile(endpoint: "192.0.2.1:443")
        let resolved = try await resolver(recorder).resolve(profile, interfaceIndex: nil)
        #expect(try resolved[profile.peers[0].publicKey] == endpoint("2001:db8::1", 443))
    }

    @Test(arguments: [false, true])
    func `a lookup that fails or finds nothing leaves the literal unchanged`(_ throwing: Bool) async throws {
        let recorder = LookupRecorder { _, _ in
            if throwing {
                throw TunnelError.backendUnavailable
            }
            return []
        }
        let profile = try profile(endpoint: "192.0.2.1:51820")
        let resolved = try await resolver(recorder).resolve(profile, interfaceIndex: nil)
        #expect(recorder.queries.count == 1)
        #expect(try resolved == [profile.peers[0].publicKey: endpoint("192.0.2.1")])
    }

    @Test
    func `the blocking lookup runs on its own queue`() async throws {
        let recorder = LookupRecorder { _, port in try [Endpoint(validatingHost: "192.0.2.1", port: port)] }
        _ = try await resolver(recorder).resolve(profile(endpoint: "192.0.2.1:51820"), interfaceIndex: nil)
        #expect(recorder.onLookupQueue == [true])
    }

    @Test
    func `a lookup past the deadline leaves the literal and its late result is discarded`() async throws {
        let clock = TestClock()
        let release = DispatchSemaphore(value: 0)
        let recorder = LookupRecorder { _, port in
            release.wait()
            return try [Endpoint(validatingHost: "64:ff9b::c000:201", port: port)]
        }
        let profile = try profile(endpoint: "192.0.2.1:51820")
        let target = resolver(recorder, clock: clock)
        let resolving = Task { try await target.resolve(profile, interfaceIndex: nil) }
        await eventually { recorder.queries.count == 1 && clock.sleeperCount == 1 }
        clock.advance(10)
        let resolved = try await resolving.value
        release.signal()
        #expect(try resolved == [profile.peers[0].publicKey: endpoint("192.0.2.1")])
        await eventually { clock.sleeperCount == 0 }
    }

    @Test
    func `cancelling the resolve ends it without a fallback`() async throws {
        let release = DispatchSemaphore(value: 0)
        let recorder = LookupRecorder { _, port in
            release.wait()
            return try [Endpoint(validatingHost: "64:ff9b::c000:201", port: port)]
        }
        let profile = try profile(endpoint: "192.0.2.1:51820")
        let target = resolver(recorder)
        let resolving = Task { try await target.resolve(profile, interfaceIndex: nil) }
        await eventually { recorder.queries.count == 1 }
        resolving.cancel()
        await #expect(throws: TunnelError.cancelled) { try await resolving.value }
        release.signal()
    }

    @Test
    func `getaddrinfo is asked for UDP datagrams of any family with address configuration on`() {
        let hints = PhysicalEndpointResolver.literalHints()
        #expect(hints.ai_family == AF_UNSPEC)
        #expect(hints.ai_socktype == SOCK_DGRAM)
        #expect(hints.ai_protocol == IPPROTO_UDP)
        #expect(hints.ai_flags == AI_ADDRCONFIG)
        #expect(hints.ai_flags & AI_NUMERICHOST == 0)
    }

    @Test
    func `a getaddrinfo list yields its IPv4 and IPv6 entries in order and skips the rest`() throws {
        let local = UnsafeMutablePointer<sockaddr_un>.allocate(capacity: 1)
        let six = UnsafeMutablePointer<sockaddr_in6>.allocate(capacity: 1)
        let four = UnsafeMutablePointer<sockaddr_in>.allocate(capacity: 1)
        defer { local.deallocate(); six.deallocate(); four.deallocate() }
        var unix = sockaddr_un()
        unix.sun_family = sa_family_t(AF_UNIX)
        local.initialize(to: unix)
        var v6 = sockaddr_in6()
        v6.sin6_family = sa_family_t(AF_INET6)
        #expect(inet_pton(AF_INET6, nat64, &v6.sin6_addr) == 1)
        six.initialize(to: v6)
        var v4 = sockaddr_in()
        v4.sin_family = sa_family_t(AF_INET)
        #expect(inet_pton(AF_INET, "192.0.2.1", &v4.sin_addr) == 1)
        four.initialize(to: v4)

        func node(
            _ address: UnsafeMutableRawPointer,
            length: Int,
            next: UnsafeMutablePointer<addrinfo>?,
        ) -> UnsafeMutablePointer<addrinfo> {
            let pointer = UnsafeMutablePointer<addrinfo>.allocate(capacity: 1)
            var info = addrinfo()
            info.ai_addr = address.assumingMemoryBound(to: sockaddr.self)
            info.ai_addrlen = socklen_t(length)
            info.ai_next = next
            pointer.initialize(to: info)
            return pointer
        }
        let tail = node(four, length: MemoryLayout<sockaddr_in>.size, next: nil)
        let middle = node(six, length: MemoryLayout<sockaddr_in6>.size, next: tail)
        let head = node(local, length: MemoryLayout<sockaddr_un>.size, next: middle)
        defer { head.deallocate(); middle.deallocate(); tail.deallocate() }
        let usable = PhysicalEndpointResolver.usableEndpoints(UnsafePointer(head), port: 51820)
        #expect(try usable == [endpoint(nat64), endpoint("192.0.2.1")])
        #expect(PhysicalEndpointResolver.usableEndpoints(nil, port: 51820).isEmpty)
    }
}
