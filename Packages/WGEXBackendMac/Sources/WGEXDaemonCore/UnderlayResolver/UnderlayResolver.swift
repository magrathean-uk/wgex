// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy

/// Endpoint resolution and cache invalidation belong to the same daemon port.
public protocol DaemonUnderlayResolving: Sendable {
    /// Compatibility entry for explicitly bound, stateless ports.
    func resolve(host: String, interfaceIndex: UInt32) async throws(DaemonFailure) -> [String]
    /// Resolves using both physical families and the primary service's DNS servers.
    func resolve(host: String, underlay: UnderlaySnapshot) async throws(DaemonFailure) -> [String]
    /// Discards cached answers after a path or service change.
    func invalidate() async
}

public extension DaemonUnderlayResolving {
    /// Legacy stateless ports resolve on the preferred physical interface.
    func resolve(host: String, underlay: UnderlaySnapshot) async throws(DaemonFailure) -> [String] {
        try await resolve(host: host, interfaceIndex: underlay.v6 ?? underlay.v4 ?? 0)
    }

    /// Stateless resolvers have no cache to invalidate.
    func invalidate() async {}
}

public protocol EngineResolveCalling: Sendable {
    func resolve(host: String, v4: UInt32?, v6: UInt32?, resolvers: [String]) async throws -> Data
}

public struct EngineResolution: Decodable, Sendable, Equatable {
    public let a: [String]?
    public let aaaa: [String]?
    public let ttl: UInt32
    public let error: String?
}

public actor UnderlayResolver: DaemonUnderlayResolving {
    private struct CacheKey: Hashable { let host: String; let underlay: UnderlaySnapshot }
    private struct Cached: Sendable { let expires: Duration; let addresses: [String] }
    private let engine: any EngineResolveCalling
    private let clock: any DaemonClock
    private var cache: [CacheKey: Cached] = [:]
    private var revision: UInt64 = 0
    public init(engine: any EngineResolveCalling, clock: any DaemonClock = ContinuousDaemonClock()) {
        self.engine = engine; self.clock = clock
    }

    public func invalidate() async {
        cache = [:]; revision &+= 1
    }

    public func resolve(host: String, interfaceIndex: UInt32) async throws(DaemonFailure) -> [String] {
        // The legacy seam cannot safely discover primary-service resolvers. Never use the host's default resolver.
        throw .portNoAnswer
    }

    public func resolve(host: String, underlay: UnderlaySnapshot) async throws(DaemonFailure) -> [String] {
        guard underlay.v4 != nil || underlay.v6 != nil, !underlay.resolvers.isEmpty,
              !host.isEmpty, host.utf8.count <= 253, !host.utf8.contains(0)
        else { throw .portNoAnswer }
        let key = CacheKey(host: host, underlay: underlay)
        if let cached = cache[key], clock.now < cached.expires {
            return cached.addresses
        }
        let queryRevision = revision
        do {
            let data = try await engine.resolve(host: host, v4: underlay.v4, v6: underlay.v6, resolvers: underlay.resolvers)
            guard data.count <= 65536 else { throw DaemonFailure.portNoAnswer }
            let decoded = try JSONDecoder().decode(EngineResolution.self, from: data)
            guard decoded.error == nil || decoded.error == "" else { throw DaemonFailure.portNoAnswer }
            let addresses = Self.order((decoded.aaaa ?? []) + (decoded.a ?? []), prefersIPv6: underlay.v6 != nil)
            guard !addresses.isEmpty else { throw DaemonFailure.portNoAnswer }
            if cache.count >= 128 {
                cache = [:]
            }
            if revision == queryRevision {
                cache[key] = Cached(expires: clock.now + .seconds(decoded.ttl), addresses: addresses)
            }
            return addresses
        } catch let error as DaemonFailure where error.isPortFailure { throw error }
        catch { throw .portNoAnswer }
    }

    /// RFC 8305 section 4: alternate families, preserve order within a family, deduplicate canonical literals.
    public nonisolated static func order(_ addresses: [String], prefersIPv6: Bool) -> [String] {
        let unique = validLiterals(addresses).compactMap { try? IPAddressRange($0) }
        let first = unique.filter { $0.isIPv6 == prefersIPv6 }.map(\.address)
        let second = unique.filter { $0.isIPv6 != prefersIPv6 }.map(\.address)
        return (0 ..< max(first.count, second.count)).flatMap { index in
            (index < first.count ? [first[index]] : []) + (index < second.count ? [second[index]] : [])
        }
    }

    public nonisolated static func validLiterals(_ addresses: [String]) -> [String] {
        var seen: Set<String> = []
        return addresses.compactMap { text -> String? in
            guard !text.contains("/"), let address = try? IPAddressRange(text), seen.insert(address.address).inserted else { return nil }
            return address.address
        }
    }
}
