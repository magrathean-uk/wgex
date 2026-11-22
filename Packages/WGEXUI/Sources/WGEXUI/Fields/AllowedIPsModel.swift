// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Editable AllowedIPs list with the "All traffic" and "Exclude private
/// networks" helpers.
public nonisolated struct AllowedIPsModel: Sendable, Hashable {
    /// One editable entry.
    public struct Entry: Sendable, Hashable, Identifiable {
        /// Stable identity within the model.
        public let id: Int
        /// Text as typed.
        public var text: String
    }

    /// Entries in order.
    public var entries: [Entry]
    private var nextID: Int

    /// Creates a model from texts.
    public init(_ texts: [String] = []) {
        entries = texts.enumerated().map { Entry(id: $0.offset, text: $0.element) }
        nextID = texts.count
    }

    /// Creates a model from a comma-separated list.
    public init(text: String) {
        self.init(text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })
    }

    /// Entry texts.
    public var texts: [String] {
        entries.map(\.text)
    }

    /// Comma-separated list, as in a configuration file.
    public var text: String {
        texts.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.joined(separator: ", ")
    }

    /// Validation per entry.
    public var validations: [FieldValidation] {
        entries.map { Self.validate($0.text) }
    }

    /// Valid entries as blocks.
    public var blocks: [CIDRBlock] {
        entries.compactMap { try? CIDRBlock(parsing: $0.text) }
    }

    /// At least one entry, and no invalid entry.
    public var isValid: Bool {
        !blocks.isEmpty && !validations.contains { $0.message != nil }
    }

    /// State of the "Exclude private networks" control for a peer (DEC-020).
    public enum PrivateNetworkExclusion: Sendable, Hashable {
        /// The IPv4 entries cover all of IPv4.
        case off
        /// The IPv4 entries cover every public IPv4 address the exclusion keeps, but not all of IPv4.
        case on
        /// Anything else, including a peer with no IPv4 entry: there is no control.
        case unavailable
    }

    /// Whether the list routes every IPv4 and IPv6 address, compared as address sets.
    public var routesAllTraffic: Bool {
        privateNetworkExclusion(dnsServers: []) == .off && coversAllIPv6
    }

    /// Whether the list is in the excluded-private state, with no DNS servers to ignore.
    public var excludesPrivateNetworks: Bool {
        privateNetworkExclusion(dnsServers: []) == .on
    }

    /// The one DEC-020 predicate behind the control, the summary and the DNS-edit path. It compares
    /// the valid IPv4 entries as address sets, ignoring the exact /32 host routes of `dnsServers`.
    /// IPv6 entries never affect it.
    public func privateNetworkExclusion(dnsServers: [String]) -> PrivateNetworkExclusion {
        let hostRoutes = Set(Self.dnsHostRoutes(dnsServers))
        let ipv4 = blocks.filter { !$0.isIPv6 && !hostRoutes.contains($0) }
        if Self.covers(ipv4, [.allIPv4]) {
            return .off
        }
        return Self.covers(ipv4, Self.publicIPv4) ? .on : .unavailable
    }

    /// One-line description of the list.
    public var summary: String {
        summaryText(dnsServers: [])
    }

    /// One-line description of the list, read through ``privateNetworkExclusion(dnsServers:)``
    /// so the DNS host routes for `dnsServers` do not change it.
    public func summaryText(dnsServers: [String]) -> String {
        switch privateNetworkExclusion(dnsServers: dnsServers) {
        case .off where coversAllIPv6:
            return MacStrings.allTraffic
        case .on:
            return coversAllIPv6 ? MacStrings.allTrafficExceptPrivateNetworks : MacStrings.allIPv4TrafficExceptPrivate
        default:
            let networks = Set(blocks.map(\.network))
            return networks.count == 1 ? MacStrings.singleRange : MacStrings.ranges(String(networks.count))
        }
    }

    /// Validates one entry.
    public static func validate(_ text: String) -> FieldValidation {
        do {
            _ = try CIDRBlock(parsing: text)
            return .valid
        } catch .empty {
            return .empty
        } catch {
            return .invalid(error.message)
        }
    }

    /// Appends an entry.
    public mutating func add(_ text: String = "") {
        entries.append(Entry(id: nextID, text: text))
        nextID += 1
    }

    /// Removes the entry with `id`.
    public mutating func remove(id: Int) {
        entries.removeAll { $0.id == id }
    }

    /// Replaces the list with `0.0.0.0/0, ::/0`.
    public mutating func setAllTraffic() {
        replace(with: [CIDRBlock.allIPv4.description, CIDRBlock.allIPv6.description])
    }

    /// Turns the "Exclude private networks" control on or off (DEC-020); nothing happens when
    /// the control is unavailable or already in that state. On replaces the IPv4 entries with the
    /// public set and appends each DNS server as a /32 or /128, skipping only exact duplicates: the
    /// daemon routes AllowedIPs only and installs a full route as two /1 halves that lose to a more
    /// specific route on the physical network, so a broader entry is not enough. Off restores
    /// `0.0.0.0/0`. Both keep every IPv6 entry and every entry that does not parse, with its identity.
    public mutating func setPrivateNetworksExcluded(_ isOn: Bool, dnsServers: [String] = []) {
        let state = privateNetworkExclusion(dnsServers: dnsServers)
        guard state != .unavailable, (state == .on) != isOn else { return }
        let kept = entries.filter { entry in (try? CIDRBlock(parsing: entry.text)).map(\.isIPv6) ?? true }
        let ipv4 = isOn ? Self.publicIPv4 : [.allIPv4]
        entries = []
        for block in ipv4 {
            add(block.description)
        }
        entries += kept
        if isOn {
            appendMissing(Self.dnsHostRoutes(dnsServers))
        }
    }

    /// Turns the "Exclude private networks" control on; see ``setPrivateNetworksExcluded(_:dnsServers:)``.
    public mutating func excludePrivateNetworks(dnsServers: [String] = []) {
        setPrivateNetworksExcluded(true, dnsServers: dnsServers)
    }

    /// Follows a DNS change from `old` to `new` (the state is judged with the servers of `old`, whose
    /// host routes the list holds). While the control is on or off, it removes every exact /32 or
    /// /128 entry equal to a server that left, whoever typed it, so an off, edit, on sequence leaves
    /// no stale route; only while on does it append the missing host route of every current server.
    /// Removal cannot change the state, which ignores those routes. With no control nothing changes.
    /// Surviving entries keep their identity.
    public mutating func reconcileDNSHostRoutes(from old: [String], to new: [String]) {
        let state = privateNetworkExclusion(dnsServers: old)
        guard state != .unavailable else { return }
        let current = Self.dnsHostRoutes(new)
        let departed = Set(Self.dnsHostRoutes(old)).subtracting(current)
        entries.removeAll { entry in (try? CIDRBlock(parsing: entry.text)).map(departed.contains) ?? false }
        if state == .on {
            appendMissing(current)
        }
    }

    /// The public IPv4 blocks left once the private ranges are subtracted from 0.0.0.0/0.
    private static let publicIPv4 = CIDRBlock.subtracting([.allIPv4], excluding: CIDRBlock.privateIPv4)

    private var coversAllIPv6: Bool {
        Self.covers(blocks.filter(\.isIPv6), [.allIPv6])
    }

    /// Whether `blocks` contain every address of `target`.
    private static func covers(_ blocks: [CIDRBlock], _ target: [CIDRBlock]) -> Bool {
        CIDRBlock.subtracting(target, excluding: blocks).isEmpty
    }

    /// Each distinct DNS server literal as its host route; text that is not an address is skipped.
    private static func dnsHostRoutes(_ servers: [String]) -> [CIDRBlock] {
        var seen = Set<CIDRBlock>()
        return servers.compactMap { try? DNSServer($0.trimmingCharacters(in: .whitespaces)).address }.filter { seen.insert($0).inserted }
    }

    /// Appends each route that is not already an exact entry.
    private mutating func appendMissing(_ routes: [CIDRBlock]) {
        for route in routes where !blocks.contains(route) {
            add(route.description)
        }
    }

    private mutating func replace(with texts: [String]) {
        entries = []
        for text in texts {
            add(text)
        }
    }
}
