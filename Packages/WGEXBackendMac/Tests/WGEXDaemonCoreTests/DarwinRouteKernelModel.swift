// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Host-only model of the XNU routing-socket behaviour behind M1-17. An RTF_HOST entry has no radix mask, so an RTM_GET
/// that carries a netmask never finds it; RTM_ADD of an existing key fails synchronously from write(2) with EEXIST
/// unless that entry is a kernel clone, which it replaces; RTF_IFSCOPE keys include the interface index. Interfaces
/// carry the kernel's ifi_lastchange (whole seconds), which moves on its own and is never part of the identity the
/// reader reports (M1-18): name and index, a utun's descriptor while this process holds it open, and a physical
/// interface's link-layer address. No descriptor is opened.
///
/// With `enforceReachability()` the model also applies XNU's ifaddr selection for RTM_ADD (rt_getifa,
/// ifa_ifwithroute) and the route a bound datagram takes (M1-19 D14, D15). An AF_LINK gateway names its interface by
/// index, and the route needs an address of the destination's family on that interface: a utun without an IPv6
/// address refuses ::/1 with ENETUNREACH. A scoped IPv4 gateway (RTF_GATEWAY | RTF_IFSCOPE) must be on link on the
/// scope interface, inside the prefix of one of its IPv4 addresses; routes on other interfaces, such as the tunnel's
/// /1 routes, play no part in that check. A datagram bound to an interface (IP_BOUND_IF, the pf evaluation canary)
/// takes the most specific route scoped to that interface; without one it follows the unscoped table only when that
/// table's best match uses the same interface, and otherwise has no route (ENETUNREACH). The unscoped default route,
/// which the model does not hold, is assumed to use the bound interface.
package final class DarwinRouteKernelModel: InterfaceIdentityReading, Sendable {
    package struct Entry: Sendable, Equatable {
        package let destination: [UInt8]
        /// nil for RTF_HOST: no radix mask.
        package let prefix: Int?
        package let scope: UInt16
        package let index: UInt16
        package let flags: UInt32
        package let gateway: [UInt8]
        /// Answers ADD's key collision but not RTM_GET: models a lookup that misses a route the kernel still holds.
        package var hidden = false
        package var gatewayAddress: String? {
            RouteMessageCodec.address(gateway)?.address
        }
    }

    /// One kernel interface. `stamp` is ifi_lastchange; `descriptor` is this process's open utun descriptor, if any.
    private struct Interface {
        var index: UInt32
        var stamp: UInt64
        var descriptor: TunnelDescriptor?
        var linkAddress: String?
        var addresses: [IPAddressRange] = []
    }

    private struct State {
        var entries: [Entry] = []
        var replies: [Int32: [Data]] = [:]
        var descriptor: Int32 = 1000
        var interfaces: [String: Interface] = [:]
        var requests: [RouteMessage] = []
        var failDeletes = false
        var reachability = false
        var failingAdds: [[UInt8]: Int32] = [:]
        var failingDeletes: [[UInt8]: Int32] = [:]
        var failedAdds = 0
        var primaryScope: UInt16?
    }

    private let state = Mutex(State())
    package init() {}

    package var entries: [Entry] {
        state.withLock { $0.entries }
    }

    package var requests: [RouteMessage] {
        state.withLock { $0.requests }
    }

    /// Makes every later RTM_DELETE fail synchronously with EPERM.
    package func failDeletes() {
        state.withLock { $0.failDeletes = true }
    }

    package var canaries: [Entry] {
        entries.filter { $0.destination == [192, 0, 2, 1] }
    }

    package var owned: [Entry] {
        entries.filter { $0.flags & 0x4000 != 0 }
    }

    package func identity(named name: String) -> TunnelIdentity? {
        state.withLock { state in state.interfaces[name].map { Self.identity(name, $0) } }
    }

    package func addresses(named name: String) -> [IPAddressRange] {
        state.withLock { $0.interfaces[name]?.addresses ?? [] }
    }

    /// Attaches a fresh kernel interface. A utun is created by this process's engine, so it is held by a new descriptor
    /// recorded for `generation`; a physical interface carries a link-layer address derived from its index. Attaching
    /// a name again is another kernel interface: the earlier descriptor never matches it.
    @discardableResult
    package func attach(
        _ name: String, index: UInt32, seconds: UInt64 = 1000, generation: Generation = .initial, held: Bool? = nil,
    ) -> TunnelIdentity {
        state.withLock { state in
            let utun = name.hasPrefix("utun")
            var descriptor: TunnelDescriptor?
            if held ?? utun {
                state.descriptor += 1; descriptor = TunnelDescriptor(fd: state.descriptor, generation: generation)
            }
            let interface = Interface(
                index: index, stamp: seconds, descriptor: descriptor,
                linkAddress: utun ? nil : String(format: "02:00:5e:00:00:%02x", index & 0xFF),
            )
            state.interfaces[name] = interface
            return Self.identity(name, interface)
        }
    }

    /// XNU moves ifi_lastchange (whole seconds) when an interface is administered after the second has turned, and on
    /// its own (guest run 6). An index change is another interface under the same name.
    @discardableResult
    package func touch(_ name: String, index: UInt32? = nil) -> TunnelIdentity? {
        state.withLock { state -> TunnelIdentity? in
            guard var interface = state.interfaces[name] else { return nil }
            interface.stamp += 1; interface.index = index ?? interface.index
            state.interfaces[name] = interface
            return Self.identity(name, interface)
        }
    }

    /// The kernel's ifi_lastchange for an interface (whole seconds); never part of the reported identity.
    package func stamp(_ name: String) -> UInt64? {
        state.withLock { $0.interfaces[name]?.stamp }
    }

    /// The engine's utun descriptor is closed (or now reports another name): this process no longer holds the utun.
    package func closeDescriptor(_ name: String) {
        state.withLock { $0.interfaces[name]?.descriptor = nil }
    }

    /// The physical interface reports another link-layer address.
    package func setLinkAddress(_ name: String, _ address: String?) {
        state.withLock { $0.interfaces[name]?.linkAddress = address }
    }

    /// SIOCAIFADDR as SystemTunnelDevice applies it.
    package func assign(_ addresses: [IPAddressRange], to name: String) {
        state.withLock { state in
            for address in addresses where state.interfaces[name]?.addresses.contains(address) == false {
                state.interfaces[name]?.addresses.append(address)
            }
        }
    }

    /// An assigned address disappears from the interface.
    package func removeAddress(_ address: IPAddressRange, from name: String) {
        state.withLock { $0.interfaces[name]?.addresses.removeAll { $0.address == address.address } }
    }

    /// Seeds a route the daemon did not install in this process (leaked, foreign or a kernel clone).
    /// `prefix` nil seeds an RTF_HOST entry.
    package func seed(
        _ destination: String, prefix: Int? = nil, scope: UInt16, index: UInt16, flags: UInt32, gateway: String,
        hidden: Bool = false,
    ) throws {
        let entry = try Entry(
            destination: IPAddressRange(destination).bytes, prefix: prefix, scope: scope, index: index, flags: flags,
            gateway: Self.sockaddr(IPAddressRange(gateway).bytes), hidden: hidden,
        )
        state.withLock { $0.entries.append(entry) }
    }

    package var operations: RouteSocketOperations {
        .init(open: { [self] in
            state.withLock { state in
                state.descriptor += 1; state.replies[state.descriptor] = []
                return state.descriptor
            }
        }, write: { [self] fd, data in
            handle(fd, data)
        }, read: { [self] fd in
            state.withLock { state in
                guard state.replies[fd]?.isEmpty == false else { return nil }
                return state.replies[fd]?.removeFirst()
            }
        }, close: { [self] fd in
            state.withLock { _ = $0.replies.removeValue(forKey: fd) }
        })
    }

    /// NET_RT_DUMP2 as RouteMessageCodec.parseDump returns it: PROTO2 entries only, as zeroed GET records.
    package func dump() throws -> [RouteMessage] {
        try owned.map { entry in
            var header = [UInt8](repeating: 0, count: RouteMessageCodec.headerLength)
            header[2] = 5; header[3] = RouteOperation.get.rawValue
            return try RouteMessageCodec.parse(Data(Self.reply(header, entry)))
        }
    }

    private func handle(_ fd: Int32, _ data: Data) -> Int32? {
        guard let message = try? RouteMessageCodec.parse(data), let destination = message.addresses[0],
              let address = RouteMessageCodec.address(destination)
        else { return EINVAL }
        let ipv6 = destination[1] == 30
        let masked = message.addresses[2].map { Self.prefix(RouteMessageCodec.maskBytes($0, ipv6: ipv6)) }
        let entry = Entry(
            destination: address.bytes, prefix: message.flags & 4 != 0 ? nil : masked,
            scope: message.flags & 0x1000000 != 0 ? message.index : 0, index: message.index, flags: message.flags,
            gateway: message.addresses[1] ?? [],
        )
        return state.withLock { state -> Int32? in
            state.requests.append(message)
            var reply = Array(data), error: Int32 = 0
            switch message.type {
            case RouteOperation.add.rawValue:
                error = Self.add(entry, to: &state)
                state.failedAdds += error == 0 ? 0 : 1
            case RouteOperation.delete.rawValue:
                error = state.failDeletes ? EPERM : state.failingDeletes[entry.destination] ?? Self.delete(entry, from: &state)
            case RouteOperation.get.rawValue:
                if let found = Self.lookup(entry, masked: masked, in: state) {
                    reply = Self.reply(Array(data.prefix(RouteMessageCodec.headerLength)), found)
                } else {
                    error = ESRCH
                }
            default: error = EOPNOTSUPP
            }
            RouteMessageCodec.put(UInt32(bitPattern: error), at: 24, into: &reply)
            state.replies[fd, default: []].append(Data(reply))
            return error == 0 ? nil : error
        }
    }

    private static func add(_ entry: Entry, to state: inout State) -> Int32 {
        if let error = state.failingAdds[entry.destination] {
            return error
        }
        if state.reachability, let error = unreachable(entry, in: state) {
            return error
        }
        if let existing = state.entries.firstIndex(where: { sameKey($0, entry) }) {
            guard state.entries[existing].flags & 0x20000 != 0 else { return EEXIST }
            state.entries.remove(at: existing)
        }
        state.entries.append(entry)
        return 0
    }

    private static func delete(_ entry: Entry, from state: inout State) -> Int32 {
        guard let existing = state.entries.firstIndex(where: { sameKey($0, entry) }) else { return ESRCH }
        state.entries.remove(at: existing)
        return 0
    }

    /// A netmask selects the exact key-mask pair, which never matches a maskless host entry; otherwise best match.
    private static func lookup(_ request: Entry, masked: Int?, in state: State) -> Entry? {
        let scoped = state.entries.filter {
            !$0.hidden && $0.scope == request.scope && $0.destination.count == request.destination.count
        }
        if let masked {
            if request.scope == 0, let primary = state.primaryScope, let found = state.entries.first(where: {
                !$0.hidden && $0.scope == primary && $0.destination == request.destination && $0.prefix == masked
            }) {
                return found
            }
            return scoped.first { $0.destination == request.destination && $0.prefix == masked }
        }
        return scoped.filter { covers($0, request.destination) }.max { width($0) < width($1) }
    }

    private static func sameKey(_ lhs: Entry, _ rhs: Entry) -> Bool {
        lhs.destination == rhs.destination && lhs.prefix == rhs.prefix && lhs.scope == rhs.scope
    }

    private static func width(_ entry: Entry) -> Int {
        entry.prefix ?? entry.destination.count * 8
    }

    private static func covers(_ entry: Entry, _ destination: [UInt8]) -> Bool {
        let mask = mask(width(entry), count: destination.count)
        return destination.indices.allSatisfy { destination[$0] & mask[$0] == entry.destination[$0] & mask[$0] }
    }

    private static func reply(_ header: [UInt8], _ entry: Entry) -> [UInt8] {
        var bytes = header, bits: UInt32 = 3
        bytes += padded(sockaddr(entry.destination)) + padded(entry.gateway)
        if let prefix = entry.prefix {
            bits |= 4
            bytes += sockaddr(mask(prefix, count: entry.destination.count))
        }
        RouteMessageCodec.put(UInt32(entry.index), at: 4, count: 2, into: &bytes)
        RouteMessageCodec.put(entry.flags, at: 8, into: &bytes)
        RouteMessageCodec.put(bits, at: 12, into: &bytes)
        RouteMessageCodec.put(UInt32(bytes.count), at: 0, count: 2, into: &bytes)
        return bytes
    }

    private static func sockaddr(_ address: [UInt8]) -> [UInt8] {
        let ipv6 = address.count == 16
        var result = [UInt8](repeating: 0, count: ipv6 ? 28 : 16)
        result[0] = UInt8(result.count); result[1] = ipv6 ? 30 : 2
        result.replaceSubrange((ipv6 ? 8 : 4) ..< (ipv6 ? 24 : 8), with: address)
        return result
    }

    private static func padded(_ bytes: [UInt8]) -> [UInt8] {
        bytes + [UInt8](repeating: 0, count: (4 - bytes.count % 4) % 4)
    }

    private static func mask(_ prefix: Int, count: Int) -> [UInt8] {
        (0 ..< count).map { index in
            let bits = min(max(prefix - index * 8, 0), 8)
            return bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
    }

    private static func prefix(_ mask: [UInt8]) -> Int {
        mask.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    private static func identity(_ name: String, _ interface: Interface) -> TunnelIdentity {
        TunnelIdentity(
            name: name, interfaceIndex: interface.index, descriptor: interface.descriptor, linkAddress: interface.linkAddress,
        )
    }
}

/// M1-19: XNU's RTM_ADD ifaddr selection and the bound canary's route (see the type's documentation).
package extension DarwinRouteKernelModel {
    /// Applies XNU's RTM_ADD ifaddr selection (see the type's documentation); off by default for the M1-17 and M1-18
    /// fixtures that install routes on an interface without assigning it addresses.
    func enforceReachability() {
        state.withLock { $0.reachability = true }
    }

    /// XNU's primary interface (get_primary_ifscope): an unscoped RTM_GET for an exact key-mask pair answers with the
    /// entry scoped to this interface when one has that key, ahead of the unscoped entry (rt_lookup_common with
    /// IFSCOPE_NONE; M08-T22, lab route monitor: the GET for the tunnel's 0.0.0.0/1 returned the en0-scoped half).
    func setPrimaryScope(_ index: UInt16) {
        state.withLock { $0.primaryScope = index }
    }

    /// Makes every later RTM_ADD of `destination` fail synchronously with `error`.
    func failAdds(of destination: String, error: Int32) throws {
        let bytes = try IPAddressRange(destination).bytes
        state.withLock { $0.failingAdds[bytes] = error }
    }

    /// Makes every later RTM_DELETE of `destination` fail synchronously with `error`; nil lets them through again.
    func failDeletes(of destination: String, error: Int32?) throws {
        let bytes = try IPAddressRange(destination).bytes
        state.withLock { $0.failingDeletes[bytes] = error }
    }

    /// How many RTM_ADD requests have failed so far.
    var failedAdds: Int {
        state.withLock { $0.failedAdds }
    }

    /// Where a datagram bound to `interfaceIndex` (IP_BOUND_IF) and sent to `destination` would go: 0 when it has a
    /// route out of that interface, ENETUNREACH when the unscoped table sends it to another interface and no route is
    /// scoped to the bound one.
    func boundSend(to destination: String, interfaceIndex: UInt32) throws -> Int32 {
        let bytes = try IPAddressRange(destination).bytes
        return state.withLock { state in
            let candidates = state.entries.filter { !$0.hidden && $0.destination.count == bytes.count && Self.covers($0, bytes) }
            if candidates.contains(where: { UInt32($0.scope) == interfaceIndex }) {
                return 0
            }
            guard let unscoped = candidates.filter({ $0.scope == 0 }).max(by: { Self.width($0) < Self.width($1) }) else { return 0 }
            return UInt32(unscoped.index) == interfaceIndex ? 0 : ENETUNREACH
        }
    }

    /// XNU's ifaddr selection for the two shapes the daemon adds; nil when the add may proceed.
    private static func unreachable(_ entry: Entry, in state: State) -> Int32? {
        let ipv6 = entry.destination.count == 16
        if entry.gateway.count >= 4, entry.gateway[1] == 18 {
            let index = UInt32(entry.gateway[2]) | UInt32(entry.gateway[3]) << 8
            let interface = state.interfaces.values.first { $0.index == index }
            return interface?.addresses.contains { $0.isIPv6 == ipv6 } == true ? nil : ENETUNREACH
        }
        guard entry.flags & 0x1000002 == 0x1000002, let gateway = RouteMessageCodec.address(entry.gateway) else { return nil }
        let interface = state.interfaces.values.first { $0.index == UInt32(entry.scope) }
        return interface?.addresses.contains { !$0.isIPv6 && $0.contains(gateway) } == true ? nil : ENETUNREACH
    }
}

/// The production socket adapter over the model's descriptor operations, plus the model's bulk dump.
package struct DarwinRouteKernel: RouteMessageExchanging {
    package let model: DarwinRouteKernelModel
    private let socket: SystemRouteSocket
    package init(model: DarwinRouteKernelModel) {
        self.model = model; socket = SystemRouteSocket(operations: model.operations)
    }

    package func exchange(_ request: Data) async throws -> RouteMessage {
        try await socket.exchange(request)
    }

    package func dump() async throws -> [RouteMessage]? {
        try model.dump()
    }
}
