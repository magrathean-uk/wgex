// SPDX-License-Identifier: MIT

import dnssd
import Foundation
import Network
import Synchronization
import WGEXCore

/// Where an excluded host name may be looked up (M08-R01 F3): the physical interface the endpoint path requires, with
/// the tunnel (`.other`) and loopback interface types prohibited, exactly as for an endpoint host name.
package struct ExclusionLookupScope: Sendable, Equatable {
    /// The provider path's physical interface index; nil takes the first available interface that is not prohibited.
    package let requiredInterfaceIndex: UInt32?
    package let prohibitedInterfaceTypes: [NWInterface.InterfaceType]

    package init(requiredInterfaceIndex: UInt32?, prohibitedInterfaceTypes: [NWInterface.InterfaceType]) {
        self.requiredInterfaceIndex = requiredInterfaceIndex; self.prohibitedInterfaceTypes = prohibitedInterfaceTypes
    }
}

/// Network connections require the selected physical interface. No application payload is sent.
/// IP literals go through `getaddrinfo` so an IPv4 literal is synthesised on a DNS64/NAT64 network (ENGINE-05).
public struct PhysicalEndpointResolver: ProviderEndpointResolving {
    /// Blocking address lookup for an IP literal; the usable results in the resolver's order. The default is `getaddrinfo`.
    package typealias LiteralLookup = @Sendable (_ host: String, _ port: UInt16) throws -> [Endpoint]
    /// Interface-scoped address lookup for one excluded host name. The default is `scopedLookup`.
    package typealias ExclusionLookup = @Sendable (_ name: String, _ scope: ExclusionLookupScope) async throws -> [IPAddressRange]
    /// The interface types a host-name lookup may never use: the tunnel and loopback.
    package static let prohibitedInterfaceTypes: [NWInterface.InterfaceType] = [.other, .loopback]

    /// Tags the queue that runs literal lookups, so a test can prove a lookup never runs on the cooperative pool.
    package static let lookupQueueKey = DispatchSpecificKey<Bool>()
    private static let lookupQueue: DispatchQueue = {
        let queue = DispatchQueue(label: "wgex.resolve.literal", qos: .userInitiated, attributes: .concurrent)
        queue.setSpecific(key: lookupQueueKey, value: true)
        return queue
    }()

    private let lookup: LiteralLookup
    private let exclusionLookup: ExclusionLookup
    private let clock: any ProviderClock

    public init() {
        self.init(lookup: Self.systemLookup, clock: SystemProviderClock())
    }

    package init(
        lookup: @escaping LiteralLookup,
        exclusionLookup: @escaping ExclusionLookup = { try await PhysicalEndpointResolver.scopedLookup(name: $0, scope: $1) },
        clock: any ProviderClock,
    ) {
        self.lookup = lookup; self.exclusionLookup = exclusionLookup; self.clock = clock
    }

    public func resolve(_ profile: TunnelProfile, interfaceIndex: UInt32?) async throws -> [PublicKey: Endpoint] {
        var result: [PublicKey: Endpoint] = [:]
        for peer in profile.peers {
            guard let endpoint = peer.endpoint else { continue }
            if (try? IPAddressRange(endpoint.host)) != nil {
                result[peer.publicKey] = try await resolveLiteral(endpoint); continue
            }
            result[peer.publicKey] = try await resolve(endpoint, interfaceIndex: interfaceIndex)
        }
        return result
    }

    /// Interface-scoped lookups (physical interface required, tunnel prohibited), one name after another within one ten
    /// second deadline. After the deadline or a cancellation no further lookup starts; the names answered by then are kept
    /// and a failing name resolves to nothing.
    public func resolveExclusions(_ names: [String], interfaceIndex: UInt32?) async -> [String: [IPAddressRange]] {
        guard !names.isEmpty else { return [:] }
        let lookup = exclusionLookup
        let scope = ExclusionLookupScope(requiredInterfaceIndex: interfaceIndex, prohibitedInterfaceTypes: Self.prohibitedInterfaceTypes)
        let found = ExclusionAnswers()
        _ = try? await withProviderDeadlineValue(clock: clock, seconds: 10) {
            for name in names {
                try Task.checkCancellation()
                let answers = await (try? lookup(name, scope)) ?? []
                try Task.checkCancellation()
                found.record(name, Array(answers.prefix(TunnelExclusions.maximumAddressesPerHost)))
            }
        }
        return found.snapshot()
    }

    /// The default exclusion lookup: the physical interface the endpoint path selects, then a DNS-SD address query
    /// scoped to that interface, so the physical network's resolvers answer and the tunnel's never do.
    package static func scopedLookup(name: String, scope: ExclusionLookupScope) async throws -> [IPAddressRange] {
        let interface = try await physicalInterface(index: scope.requiredInterfaceIndex, prohibited: scope.prohibitedInterfaceTypes)
        return try await ScopedAddressQuery.run(name: name, interfaceIndex: UInt32(interface.index))
    }

    /// The first available interface of the current path that is not prohibited, matching `index` when one is given.
    private static func physicalInterface(index: UInt32?, prohibited: [NWInterface.InterfaceType]) async throws -> NWInterface {
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: prohibited)
        let (paths, pathContinuation) = AsyncStream<NWPath>.makeStream(bufferingPolicy: .bufferingNewest(1))
        monitor.pathUpdateHandler = { pathContinuation.yield($0) }
        monitor.start(queue: DispatchQueue(label: "wgex.resolve.path"))
        defer { monitor.cancel(); pathContinuation.finish() }
        var iterator = paths.makeAsyncIterator()
        guard let path = await iterator.next(), path.status == .satisfied,
              let interface = path.availableInterfaces.first(where: { index == nil || UInt32($0.index) == index }),
              !prohibited.contains(interface.type)
        else { throw TunnelError.backendUnavailable }
        return interface
    }

    /// A lookup that fails, times out or finds nothing leaves the literal unchanged, so a dual-stack or IPv4 network never
    /// breaks. Only cancellation propagates. The blocking call runs on its own queue; a late result is discarded.
    private func resolveLiteral(_ endpoint: Endpoint) async throws -> Endpoint {
        let lookup = lookup
        do {
            let found = try await withProviderDeadlineValue(clock: clock, seconds: 10) {
                try await withCheckedThrowingContinuation { continuation in
                    Self.lookupQueue.async {
                        continuation.resume(with: Result { try lookup(endpoint.host, endpoint.port) })
                    }
                }
            }
            return found.first ?? endpoint
        } catch TunnelError.cancelled {
            throw TunnelError.cancelled
        } catch {
            return endpoint
        }
    }

    /// `AF_UNSPEC` with UDP datagram hints. `AI_ADDRCONFIG` is the one flag set: it restricts the answer to the address
    /// families the host has configured, which on an IPv6-only DNS64/NAT64 network makes `getaddrinfo` return the
    /// synthesised IPv6 address for an IPv4 literal (Apple's IPv6-only network guidance) instead of an unreachable IPv4 one.
    /// `AI_NUMERICHOST` must stay off: it would stop the lookup before any synthesis. A non-zero `ai_flags` also replaces the
    /// implicit `AI_DEFAULT`; its other half, `AI_V4MAPPED_CFG`, is ignored for `AF_UNSPEC`.
    package static func literalHints() -> addrinfo {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = AI_ADDRCONFIG
        return hints
    }

    package static func systemLookup(host: String, port: UInt16) throws -> [Endpoint] {
        var hints = literalHints()
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &list) == 0 else { throw TunnelError.backendUnavailable }
        defer { freeaddrinfo(list) }
        return usableEndpoints(UnsafePointer(list), port: port)
    }

    /// The IPv4 and IPv6 entries of a `getaddrinfo` list in the resolver's order; anything else is skipped.
    package static func usableEndpoints(_ list: UnsafePointer<addrinfo>?, port: UInt16) -> [Endpoint] {
        var endpoints: [Endpoint] = []
        var node = list
        while let info = node?.pointee {
            defer { node = UnsafePointer(info.ai_next) }
            guard let address = info.ai_addr, let text = numericHost(address, length: Int(info.ai_addrlen)),
                  let endpoint = try? Endpoint(validatingHost: text, port: port)
            else { continue }
            endpoints.append(endpoint)
        }
        return endpoints
    }

    private static func text(_ buffer: [CChar]) -> String {
        String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    fileprivate static func numericHost(_ address: UnsafePointer<sockaddr>, length: Int) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch Int32(address.pointee.sa_family) {
        case AF_INET where length >= MemoryLayout<sockaddr_in>.size:
            var raw = UnsafeRawPointer(address).load(as: sockaddr_in.self).sin_addr
            return inet_ntop(AF_INET, &raw, &buffer, socklen_t(buffer.count)) == nil ? nil : text(buffer)
        case AF_INET6 where length >= MemoryLayout<sockaddr_in6>.size:
            var raw = UnsafeRawPointer(address).load(as: sockaddr_in6.self).sin6_addr
            return inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)) == nil ? nil : text(buffer)
        default:
            return nil
        }
    }

    private func resolve(_ endpoint: Endpoint, interfaceIndex: UInt32?) async throws -> Endpoint {
        let interface = try await Self.physicalInterface(index: interfaceIndex, prohibited: Self.prohibitedInterfaceTypes)
        let parameters = NWParameters.udp
        parameters.prohibitedInterfaceTypes = Self.prohibitedInterfaceTypes
        parameters.requiredInterface = interface
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else { throw TunnelError.backendUnavailable }
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: parameters)
        let (states, continuation) = AsyncStream<NWConnection.State>.makeStream(bufferingPolicy: .bufferingNewest(8))
        connection.stateUpdateHandler = { continuation.yield($0) }
        connection.start(queue: DispatchQueue(label: "wgex.resolve.endpoint"))
        defer { connection.cancel(); continuation.finish() }
        return try await Self.resolveStates(states, clock: SystemProviderClock()) {
            guard case let .hostPort(host, _) = connection.currentPath?.remoteEndpoint,
                  let literal = try? IPAddressRange(String(describing: host))
            else { throw TunnelError.backendUnavailable }
            return try Endpoint(validatingHost: literal.address, port: endpoint.port)
        }
    }

    /// A waiting connection can recover, but DNS/no-route waits cannot extend the deadline.
    package static func resolveStates(
        _ states: AsyncStream<NWConnection.State>, clock: any ProviderClock,
        readyEndpoint: @escaping @Sendable () throws -> Endpoint,
    ) async throws -> Endpoint {
        try await withProviderDeadlineValue(clock: clock, seconds: 10) {
            for await state in states {
                switch state {
                case .ready: return try readyEndpoint()
                case .failed, .cancelled: throw TunnelError.backendUnavailable
                case .waiting: continue // Bounded by the same deadline, including repeated waits.
                default: continue
                }
            }
            throw TunnelError.cancelled
        }
    }
}

/// Answers collected by `resolveExclusions`; written by the lookup task, read once the deadline returns.
private final class ExclusionAnswers: Sendable {
    private let answers = Mutex<[String: [IPAddressRange]]>([:])

    func record(_ name: String, _ found: [IPAddressRange]) {
        answers.withLock { $0[name] = found }
    }

    func snapshot() -> [String: [IPAddressRange]] {
        answers.withLock { $0 }
    }
}

/// One `DNSServiceGetAddrInfo` query for IPv4 and IPv6 addresses on one interface index. Every DNS-SD call and all state
/// stay on `queue`. It ends when both families have answered, two seconds after the first address, on a DNS-SD error
/// or timeout (with the addresses found so far), or on cancellation.
private final class ScopedAddressQuery: @unchecked Sendable {
    private let queue = DispatchQueue(label: "wgex.resolve.exclusion")
    private var reference: DNSServiceRef?
    private var continuation: CheckedContinuation<[IPAddressRange], any Error>?
    private var addresses: [IPAddressRange] = []
    private var answeredFamilies: Set<Int32> = []
    private var graceStarted = false
    private var cancelled = false

    static func run(name: String, interfaceIndex: UInt32) async throws -> [IPAddressRange] {
        let query = ScopedAddressQuery()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                query.queue.async { query.start(name: name, interfaceIndex: interfaceIndex, continuation: continuation) }
            }
        } onCancel: {
            query.queue.async {
                query.cancelled = true
                query.finish(.failure(CancellationError()))
            }
        }
    }

    private func start(name: String, interfaceIndex: UInt32, continuation: CheckedContinuation<[IPAddressRange], any Error>) {
        // A cancellation can reach the queue before the start does.
        guard !cancelled else {
            continuation.resume(throwing: CancellationError())
            return
        }
        self.continuation = continuation
        let context = Unmanaged.passRetained(self).toOpaque()
        var created: DNSServiceRef?
        let flags = DNSServiceFlags(kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsTimeout)
        let protocols = DNSServiceProtocol(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6)
        let status = DNSServiceGetAddrInfo(&created, flags, interfaceIndex, protocols, name, { _, flags, _, error, _, address, _, context in
            guard let context else { return }
            Unmanaged<ScopedAddressQuery>.fromOpaque(context).takeUnretainedValue().reply(flags: flags, error: error, address: address)
        }, context)
        guard Int(status) == kDNSServiceErr_NoError, let created else {
            Unmanaged<ScopedAddressQuery>.fromOpaque(context).release()
            finish(.failure(TunnelError.backendUnavailable))
            return
        }
        reference = created
        DNSServiceSetDispatchQueue(created, queue)
    }

    private func reply(flags: DNSServiceFlags, error: DNSServiceErrorType, address: UnsafePointer<sockaddr>?) {
        guard continuation != nil else { return }
        let family = address.map { Int32($0.pointee.sa_family) }
        switch Int(error) {
        case kDNSServiceErr_NoError:
            if let address, let family, flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
               let text = PhysicalEndpointResolver.numericHost(address, length: Int(address.pointee.sa_len)),
               let range = try? IPAddressRange(text)
            {
                answeredFamilies.insert(family)
                addresses.append(range)
            }
        case kDNSServiceErr_NoSuchRecord:
            if let family {
                answeredFamilies.insert(family)
            }
        default:
            finish(.success(addresses)); return
        }
        guard flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 else { return }
        if answeredFamilies.isSuperset(of: [AF_INET, AF_INET6]) || addresses.count >= TunnelExclusions.maximumAddressesPerHost {
            finish(.success(addresses))
        } else if !addresses.isEmpty, !graceStarted {
            graceStarted = true
            queue.asyncAfter(deadline: .now() + 2) { [self] in finish(.success(addresses)) }
        }
    }

    /// Runs on `queue`: deallocating there guarantees no callback follows, so the retained context can go.
    private func finish(_ result: Result<[IPAddressRange], any Error>) {
        guard let continuation else { return }
        self.continuation = nil
        if let reference {
            DNSServiceRefDeallocate(reference)
            self.reference = nil
            Unmanaged.passUnretained(self).release()
        }
        continuation.resume(with: result)
    }
}
