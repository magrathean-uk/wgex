// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonProtocol

/// In-memory Darwin route replies; no system descriptor or interface is opened.
public actor FakeRouteKernel: RouteMessageExchanging, InterfaceIdentityReading {
    /// Number of bulk route snapshots requested.
    public private(set) var dumpCount = 0
    /// Ordered route messages received by the fixture.
    public private(set) var requests: [RouteMessage] = []
    private var getFailure: DaemonFailure?
    /// Fails one lookup without touching the in-memory table.
    public func failNextGet(_ failure: DaemonFailure) {
        getFailure = failure
    }

    private var entries: [String: RouteMessage] = [:]
    private var identities: [String: TunnelIdentity] = [:]
    private var assigned: [String: [IPAddressRange]] = [:]
    /// Creates the inert fixture with explicitly supplied state.
    public init() {}
    /// Returns an atomic in-memory snapshot without RTM_GET requests.
    public func dump() -> [RouteMessage]? {
        dumpCount += 1
        return Array(entries.values)
    }

    /// Sets the identity (name, index, descriptor, link address) observed by subsequent fixture lookups.
    public func setIdentity(_ identity: TunnelIdentity) {
        identities[identity.name] = identity
    }

    /// Reads the fixture identity for an interface name.
    public func identity(named name: String) -> TunnelIdentity? {
        identities[name]
    }

    /// Sets the addresses the fixture reports as assigned to an interface.
    public func setAddresses(_ addresses: [IPAddressRange], named name: String) {
        assigned[name] = addresses
    }

    /// Reads the fixture addresses of an interface; none unless set.
    public func addresses(named name: String) -> [IPAddressRange] {
        assigned[name] ?? []
    }

    /// Installs a recorded route reply in memory.
    public func seed(_ message: RouteMessage) {
        entries[key(message)] = message
    }

    /// Clears the fixture route table.
    public func eraseAll() {
        entries = [:]
    }

    /// Applies a route message to the fixture table and returns its synthetic acknowledgement.
    public func exchange(_ request: Data) throws -> RouteMessage {
        let message = try RouteMessageCodec.parse(request)
        requests.append(message)
        if message.type == 4, let failure = getFailure {
            getFailure = nil; throw failure
        }
        let key = key(message)
        var reply = Array(request)
        switch message.type {
        case 1:
            if entries[key] == nil {
                entries[key] = message
            } else {
                RouteMessageCodec.put(UInt32(EEXIST), at: 24, into: &reply)
            }
        case 2:
            if entries.removeValue(forKey: key) == nil {
                RouteMessageCodec.put(UInt32(ESRCH), at: 24, into: &reply)
            }
        case 3: entries[key] = message
        default:
            if let entry = entries[key] {
                reply = Array(request.prefix(RouteMessageCodec.headerLength))
                for (_, address) in entry.addresses.sorted(by: { $0.key < $1.key }) {
                    reply += address
                    while reply.count % 4 != 0 {
                        reply.append(0)
                    }
                }
                RouteMessageCodec.put(UInt32(reply.count), at: 0, count: 2, into: &reply)
                RouteMessageCodec.put(entry.flags, at: 8, into: &reply)
                RouteMessageCodec.put(UInt32(entry.index), at: 4, count: 2, into: &reply)
            } else {
                RouteMessageCodec.put(UInt32(ESRCH), at: 24, into: &reply)
            }
        }
        return try RouteMessageCodec.parse(Data(reply))
    }

    private func key(_ message: RouteMessage) -> String {
        "\(message.addresses[0] ?? []):\(message.addresses[2] ?? [])"
    }
}
