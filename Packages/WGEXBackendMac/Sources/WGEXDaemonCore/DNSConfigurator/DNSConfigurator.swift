// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol

public struct SyntheticDNSValue: Sendable, Equatable {
    public let configuration: DNSConfiguration
    public let searchOrder: Int
    public init(configuration: DNSConfiguration, searchOrder: Int) throws {
        guard searchOrder >= 0, !configuration.servers.isEmpty,
              configuration.servers.allSatisfy({ !$0.contains("/") && (try? IPAddressRange($0)) != nil }),
              (configuration.searchDomains + configuration.matchDomains).allSatisfy({
                  $0.utf8.count <= 253 && $0.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }
              }) else { throw DaemonFailure.portSystem(code: EINVAL) }
        self.configuration = DNSConfiguration(
            servers: configuration.servers, searchDomains: configuration.searchDomains,
            matchDomains: configuration.matchDomains.isEmpty ? [""] : configuration.matchDomains,
        )
        self.searchOrder = searchOrder
    }
}

public protocol DNSSession: Sendable {
    func read(key: String) async throws -> SyntheticDNSValue?
    func remove(key: String) async throws
    func addTemporary(key: String, value: SyntheticDNSValue) async throws
    func resolverListing() async throws -> String
}

/// Synthetic DNS mutation and observation use the canonical daemon failure type.
public protocol DaemonDNSConfiguring: Sendable {
    /// Publishes this generation's synthetic resolver configuration.
    func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure)
    /// Removes this generation's owned DNS key.
    func remove(generation: Generation) async throws(DaemonFailure)
    /// Reports the configuration currently observed in configd.
    func current() async -> DNSConfiguration?
    /// Checks the journalled key and resolver ordering; unsupported verification fails closed.
    func verify(_ resources: GenerationResources) async throws
    /// Reads exactly this configd key; a missing key never proves ownership.
    func read(key: String) async throws -> SyntheticDNSValue?
}

public extension DaemonDNSConfiguring {
    /// Ports without a configd reader cannot claim ownership of a DNS key.
    func read(key _: String) async throws -> SyntheticDNSValue? {
        nil
    }

    /// A port without verification support requests idempotent reapplication.
    func verify(_: GenerationResources) async throws {
        throw DaemonFailure.portNotOwned
    }
}

public actor DNSConfigurator: DaemonDNSConfiguring {
    private let journal: any DaemonJournalling
    private let session: any DNSSession
    private let searchOrder: Int
    private let slot = SerialOperationSlot()
    private var published: [String: SyntheticDNSValue] = [:]
    /// SearchOrder is provisional until the DNS precedence lab spike. No primary IPv4 entity is written.
    public init(journal: any DaemonJournalling, session: any DNSSession, searchOrder: Int = 1) {
        self.journal = journal; self.session = session; self.searchOrder = searchOrder
    }

    public static func key(profileID: UUID) -> String {
        "State:/Network/Service/\(profileID.uuidString)/DNS"
    }

    public func apply(_ configuration: DNSConfiguration, generation: Generation) async throws(DaemonFailure) {
        try await slot.acquirePort(); defer { slot.release() }
        do {
            let resource = try resource(generation)
            guard resource.dns == configuration, let key = resource.dnsKey else { throw DaemonFailure.portNotOwned }
            let value = try SyntheticDNSValue(configuration: configuration, searchOrder: searchOrder)
            // Conditional removal preserves an administrator's replacement. Updates always remove then add.
            if let existing = try await session.read(key: key), existing != value, published[key] != existing {
                throw DaemonFailure.portNotOwned
            }
            try await session.remove(key: key)
            try await session.addTemporary(key: key, value: value)
            published[key] = value
        } catch let error as DaemonFailure where error.isPortFailure { throw error }
        catch { throw .portSystem(code: EIO) }
    }

    public func remove(generation: Generation) async throws(DaemonFailure) {
        try await slot.acquirePort(); defer { slot.release() }
        do {
            guard let resource = journal.snapshot().resources.first(where: { $0.generation == generation }),
                  let key = resource.dnsKey, let configuration = resource.dns else { return }
            let expected = try SyntheticDNSValue(configuration: configuration, searchOrder: searchOrder)
            guard let existing = try await session.read(key: key), existing == expected else { return }
            try await session.remove(key: key)
            published.removeValue(forKey: key)
        } catch let error as DaemonFailure where error.isPortFailure { throw error }
        catch { throw .portSystem(code: EIO) }
    }

    /// Reads the actual synthetic value through the configd session, without consulting expected resources.
    public func read(key: String) async throws -> SyntheticDNSValue? {
        try await session.read(key: key)
    }

    public func current() async -> DNSConfiguration? {
        guard let resource = journal.snapshot().resources.last(where: { $0.dnsKey != nil }), let key = resource.dnsKey else { return nil }
        return try? await session.read(key: key)?.configuration
    }

    public func verify(_ resources: GenerationResources) async throws {
        guard let configuration = resources.dns, let key = resources.dnsKey else { return }
        let expected = try SyntheticDNSValue(configuration: configuration, searchOrder: searchOrder)
        guard try await session.read(key: key) == expected else { throw DaemonFailure.portNotOwned }
        let listing = try await session.resolverListing()
        guard ScutilDNSParser.verifies(
            expected,
            in: listing,
            interfaceName: resources.identity?.name,
            interfaceIndex: resources.identity?.interfaceIndex,
        )
        else { throw DaemonFailure.portSystem(code: EIO) }
    }

    private func resource(_ generation: Generation) throws -> GenerationResources {
        let document = journal.snapshot()
        guard document.generation == generation,
              let resource = document.resources.first(where: { $0.generation == generation }),
              let profileID = document.intent?.profileID, resource.dnsKey == Self.key(profileID: profileID)
        else { throw DaemonFailure.portNotOwned }
        return resource
    }
}
