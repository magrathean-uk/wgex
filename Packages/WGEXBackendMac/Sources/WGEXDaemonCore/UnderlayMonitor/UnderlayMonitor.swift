// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public struct UnderlayEvent: Sendable, Equatable {
    public let snapshot: UnderlaySnapshot
    public let satisfied: Bool
    public let mtu: UInt16
    /// A transient configd read failure; observation remains live.
    public let readFailed: Bool
    public init(snapshot: UnderlaySnapshot, satisfied: Bool, mtu: UInt16 = 1500, readFailed: Bool = false) {
        self.snapshot = snapshot; self.satisfied = satisfied; self.mtu = mtu; self.readFailed = readFailed
    }
}

public protocol UnderlayMonitoring: Sendable {
    func start() async throws -> AsyncStream<UnderlayEvent>
    func stop() async
}

public struct UnderlayMonitorModel: Sendable {
    public private(set) var current: UnderlayEvent?
    public init() {}
    @discardableResult
    public mutating func receive(_ event: UnderlayEvent) -> Bool {
        guard current != event else { return false }
        current = event; return true
    }

    public static func mtu(override: UInt16?, underlay: UInt16, carrier: Bool) -> UInt16 {
        // Reject impossibly small MTUs in the device adapter rather than silently exceeding the underlay.
        min(override ?? 1500, underlay > 80 ? underlay - 80 : 0, carrier ? 1420 : 1500, 1500)
    }

    /// Only configd primary entities choose the interface. NWPath is a secondary change/reachability signal.
    public static func snapshot(
        ipv4: [String: String], ipv6: [String: String], indexes: [String: UInt32], resolvers: [String], lanSubnets: [IPAddressRange] = [],
    ) -> UnderlaySnapshot {
        let name4 = ipv4["PrimaryInterface"], name6 = ipv6["PrimaryInterface"]
        func index(_ name: String?) -> UInt32? {
            guard let name, let value = indexes[name], value > 0 else { return nil }
            return value
        }
        let router = ipv6["Router"].flatMap { $0.split(separator: "%").first }.flatMap { try? IPAddressRange(String($0)) }
        return UnderlaySnapshot(
            v4: index(name4), v6: index(name6), resolvers: resolvers,
            interfaceNames: Array(Set([name4, name6].compactMap(\.self))).sorted(),
            interfaceV4Name: index(name4) == nil ? nil : name4, interfaceV6Name: index(name6) == nil ? nil : name6, lanSubnets: lanSubnets,
            ipv6DefaultRouteAvailable: index(name6) != nil && router?.isIPv6 == true && router?.bytes.contains(where: { $0 != 0 }) == true,
            ipv4Router: ipv4["Router"],
        )
    }
}

package extension UnderlayMonitorModel {
    /// Rejects missing, noncontiguous and default masks rather than widening a LAN exemption.
    static func lanSubnets(addresses: [String], masks: [String], addressesV6: [String], prefixes: [Int]) -> [IPAddressRange] {
        var result: [IPAddressRange] = []
        for (address, mask) in zip(addresses, masks) {
            guard let ip = try? IPAddressRange(address), !ip.isIPv6, !address.contains("/"),
                  let bits = try? IPAddressRange(mask), !bits.isIPv6, !mask.contains("/") else { continue }
            let binary = bits.bytes.flatMap { byte in (0 ..< 8).map { byte & (0x80 >> $0) != 0 } }
            let prefix = binary.prefix(while: \.self).count
            guard prefix > 0, binary.dropFirst(prefix).allSatisfy({ !$0 }),
                  let subnet = try? IPAddressRange(validatingBytes: ip.bytes, prefixLength: prefix) else { continue }
            result.append(subnet.network)
        }
        for (address, prefix) in zip(addressesV6, prefixes) {
            guard prefix > 0, prefix <= 128, !address.contains("/"),
                  let ip = try? IPAddressRange(address), ip.isIPv6,
                  let subnet = try? IPAddressRange(validatingBytes: ip.bytes, prefixLength: prefix) else { continue }
            result.append(subnet.network)
        }
        return Array(Set(result)).sorted()
    }
}
