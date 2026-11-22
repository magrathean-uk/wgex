// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol

public enum RouteOperation: UInt8, Sendable, CaseIterable {
    case add = 1, delete = 2, change = 3, get = 4
}

/// Darwin rt_msghdr (92 bytes), little endian, followed by 32-bit-aligned sockaddrs.
/// No native pointer loads: recorded messages may be truncated or unaligned.
public struct RouteMessage: Sendable, Equatable {
    public let type: UInt8
    public let index: UInt16
    public let flags: UInt32
    public let pid: Int32
    public let sequence: Int32
    public let error: Int32
    public let addresses: [Int: [UInt8]]

    public var hasOwnershipMark: Bool {
        flags & 0x4000 != 0
    }

    public func matches(_ route: RouteSpec, index: UInt32) -> Bool {
        guard let key = RouteLookupKey(message: self), let expected = RouteLookupKey(route: route, index: index) else { return false }
        return key == expected
    }
}

public enum RouteMessageCodec {
    public static let headerLength = 92

    public static func build(
        _ operation: RouteOperation, route: RouteSpec, index: UInt32, sequence: Int32, pid: Int32, gateway: String? = nil,
    ) throws -> Data {
        guard let shortIndex = UInt16(exactly: index), index > 0, sequence > 0,
              !route.destination.contains("/"), let range = try? IPAddressRange("\(route.destination)/\(route.prefixLength)"),
              !range.hasHostBits, !route.interfaceName.isEmpty
        else { throw DaemonFailure.routeInvalidRoute }
        var bytes = [UInt8](repeating: 0, count: headerLength)
        bytes[2] = 5; bytes[3] = operation.rawValue
        put(UInt32(shortIndex), at: 4, count: 2, into: &bytes)
        // UP | STATIC | PROTO2. Tunnel routes use AF_LINK; only the TEST-NET-1 canary and the
        // port-exclusion /1 halves (OwnedCanaryRoute) may use a scoped IPv4 router gateway (validated below).
        let host = range.prefixLength == range.bytes.count * 8
        put(0x4801 | (host ? 4 : 0) | (gateway == nil ? 0 : 0x1000002), at: 8, into: &bytes)
        // A host route has no radix mask. RTM_GET matches the key-mask pair, so a /32 or /128
        // netmask never finds an RTF_HOST entry (M1-17 D13); ADD and DELETE ignore it for RTF_HOST.
        put(host ? 3 : 7, at: 12, into: &bytes)
        put(UInt32(bitPattern: pid), at: 16, into: &bytes)
        put(UInt32(bitPattern: sequence), at: 20, into: &bytes)
        bytes += sockaddr(range.bytes, ipv6: range.isIPv6)
        if let gateway {
            guard let address = try? IPAddressRange(gateway), !address.isIPv6, !range.isIPv6,
                  !gateway.contains("/"), scopedUnderlay(range)
            else { throw DaemonFailure.routeInvalidRoute }
            bytes += sockaddr(address.bytes, ipv6: false)
        } else {
            var link = [UInt8](repeating: 0, count: 8)
            link[0] = 8; link[1] = 18
            put(UInt32(shortIndex), at: 2, count: 2, into: &link)
            bytes += link
        }
        if !host {
            bytes += sockaddr(mask(range), ipv6: range.isIPv6)
        }
        put(UInt32(bytes.count), at: 0, count: 2, into: &bytes)
        return Data(bytes)
    }

    /// The only destinations a gatewayed (scoped underlay) route may have: the canary host and the two IPv4 /1 halves.
    package static func scopedUnderlay(_ range: IPAddressRange) -> Bool {
        !range.isIPv6 && ((range.address == "192.0.2.1" && range.prefixLength == 32)
            || (["0.0.0.0", "128.0.0.0"].contains(range.address) && range.prefixLength == 1))
    }

    public static func parse(_ data: Data) throws -> RouteMessage {
        let bytes = Array(data)
        guard bytes.count >= headerLength, integer(bytes, 0, 2) == bytes.count, bytes[2] == 5 else {
            throw DaemonFailure.routeMalformed
        }
        guard (1 ... 4).contains(bytes[3]) else { throw DaemonFailure.routeUnsupported }
        let bits = integer(bytes, 12, 4)
        guard bits & ~0xFF == 0 else { throw DaemonFailure.routeUnsupported }
        var offset = headerLength, addresses: [Int: [UInt8]] = [:]
        for slot in 0 ..< 8 where bits & (1 << slot) != 0 {
            guard offset + 2 <= bytes.count else { throw DaemonFailure.routeMalformed }
            let length = Int(bytes[offset]), padded = length == 0 ? 4 : (length + 3) & ~3
            guard length == 0 || length >= 2, offset + padded <= bytes.count else { throw DaemonFailure.routeMalformed }
            addresses[slot] = Array(bytes[offset ..< offset + max(length, 2)])
            offset += padded
        }
        guard offset == bytes.count else { throw DaemonFailure.routeMalformed }
        return RouteMessage(
            type: bytes[3], index: UInt16(integer(bytes, 4, 2)), flags: integer(bytes, 8, 4),
            pid: Int32(bitPattern: integer(bytes, 16, 4)), sequence: Int32(bitPattern: integer(bytes, 20, 4)),
            error: Int32(bitPattern: integer(bytes, 24, 4)), addresses: addresses,
        )
    }

    /// Decodes Darwin rt_msghdr2 records; its sockaddr offset matches rt_msghdr.
    public static func parseDump(_ data: Data) throws -> [RouteMessage] {
        let bytes = Array(data)
        var offset = 0, messages: [RouteMessage] = []
        while offset < bytes.count {
            guard offset + headerLength <= bytes.count else { throw DaemonFailure.routeMalformed }
            let length = Int(integer(bytes, offset, 2))
            guard length >= headerLength, offset + length <= bytes.count else { throw DaemonFailure.routeMalformed }
            if integer(bytes, offset + 8, 4) & 0x4000 == 0 {
                offset += length; continue
            }
            var message = Array(bytes[offset ..< offset + length])
            guard message[3] == 20 else { throw DaemonFailure.routeUnsupported }
            message[3] = RouteOperation.get.rawValue
            // refcnt, parentflags and reserved occupy pid/seq/errno positions in rt_msghdr2.
            for index in 16 ..< 28 {
                message[index] = 0
            }
            try messages.append(parse(Data(message)))
            offset += length
        }
        return messages
    }

    public static func isReply(_ message: RouteMessage, operation: RouteOperation, sequence: Int32, pid: Int32) -> Bool {
        message.type == operation.rawValue && message.sequence == sequence && message.pid == pid
    }

    package static func integer(_ bytes: [UInt8], _ offset: Int, _ count: Int) -> UInt32 {
        (0 ..< count).reduce(0) { $0 | UInt32(bytes[offset + $1]) << (8 * $1) }
    }

    package static func put(_ value: UInt32, at offset: Int, count: Int = 4, into bytes: inout [UInt8]) {
        for index in 0 ..< count {
            bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (8 * index))
        }
    }

    package static func mask(_ range: IPAddressRange) -> [UInt8] {
        range.bytes.indices.map { index in
            let bits = min(max(range.prefixLength - index * 8, 0), 8)
            return bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
    }

    private static func sockaddr(_ address: [UInt8], ipv6: Bool) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: ipv6 ? 28 : 16)
        result[0] = UInt8(result.count); result[1] = ipv6 ? 30 : 2
        result.replaceSubrange((ipv6 ? 8 : 4) ..< (ipv6 ? 24 : 8), with: address)
        return result
    }

    package static func address(_ sockaddr: [UInt8]) -> IPAddressRange? {
        guard sockaddr.count >= 2 else { return nil }
        let ipv6 = sockaddr[1] == 30
        guard ipv6 || sockaddr[1] == 2 else { return nil }
        let offset = ipv6 ? 8 : 4, width = ipv6 ? 16 : 4
        guard sockaddr.count >= offset + width else { return nil }
        return try? IPAddressRange(validatingBytes: Array(sockaddr[offset ..< offset + width]), prefixLength: width * 8)
    }

    package static func maskBytes(_ sockaddr: [UInt8], ipv6: Bool) -> [UInt8] {
        let offset = ipv6 ? 8 : 4, width = ipv6 ? 16 : 4
        return (0 ..< width).map { offset + $0 < sockaddr.count ? sockaddr[offset + $0] : 0 }
    }
}

/// Counts route-key operations made inside one task tree (a construction, a hash, a comparison), so a test can bound the
/// cost of matching a route table by operation count instead of by wall clock. A lookup that compares stored keys without
/// building any is counted as well (M1-30 NF3). Counting exists in debug builds only (M1-31): there `record()` is one
/// task-local read, and nothing is allocated or locked unless a task installed a counter. In an optimised build `record()`
/// is empty, because that read cannot be inlined away and cost about 10 ns per hash or comparison in an optimised model of
/// this key (M1-30 verify, NF4). Every test that reads the counter runs in debug (`swift test`, the lab build and
/// ThreadSanitizer are all debug configurations). The suite skips itself in any other build by the test target's own
/// `DEBUG`, not by `isCounting`; in debug a false `isCounting` fails the suite's first test.
package enum RouteMatchCost {
    @TaskLocal package static var counter: Counter?

    package final class Counter: Sendable {
        private let count = Mutex(0)
        package init() {}
        package var operations: Int {
            count.withLock { $0 }
        }

        fileprivate func record() {
            count.withLock { $0 += 1 }
        }
    }

    /// Whether `record()` counts in this build.
    package static let isCounting: Bool = {
        #if DEBUG
            true
        #else
            false
        #endif
    }()

    @inline(__always)
    fileprivate static func record() {
        #if DEBUG
            counter?.record()
        #endif
    }
}

/// Binary exact-match index; each destination and mask is parsed once per snapshot. Equality and hashing are written out
/// (the member-wise result, in the same order) so that `RouteMatchCost` sees every comparison and hash, not only the
/// constructions.
package struct RouteLookupKey: Hashable {
    private let index: UInt32
    private let destination: [UInt8]
    private let prefix: Int
    package static func == (lhs: Self, rhs: Self) -> Bool {
        RouteMatchCost.record()
        return lhs.index == rhs.index && lhs.destination == rhs.destination && lhs.prefix == rhs.prefix
    }

    package func hash(into hasher: inout Hasher) {
        RouteMatchCost.record()
        hasher.combine(index); hasher.combine(destination); hasher.combine(prefix)
    }

    package init?(route: RouteSpec, index: UInt32) {
        RouteMatchCost.record()
        let ipv6 = route.destination.utf8.contains(58), width = ipv6 ? 16 : 4
        guard route.prefixLength <= width * 8 else { return nil }
        var bytes = [UInt8](repeating: 0, count: width)
        let status = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return 0 }
            return route.destination.withCString { inet_pton(ipv6 ? AF_INET6 : AF_INET, $0, base) }
        }
        guard status == 1 else { return nil }
        for offset in bytes.indices {
            let bits = min(max(Int(route.prefixLength) - offset * 8, 0), 8)
            bytes[offset] &= bits == 0 ? 0 : UInt8.max << (8 - bits)
        }
        self.index = index; destination = bytes; prefix = Int(route.prefixLength)
    }

    package init?(message: RouteMessage) {
        RouteMatchCost.record()
        guard let address = message.addresses[0], address.count >= 2 else { return nil }
        let ipv6 = address[1] == 30, width = ipv6 ? 16 : 4, offset = ipv6 ? 8 : 4
        guard ipv6 || address[1] == 2, address.count >= offset + width else { return nil }
        index = UInt32(message.index); destination = Array(address[offset ..< offset + width])
        if message.flags & 4 != 0 {
            prefix = width * 8; return
        }
        let mask = message.addresses[2].map { RouteMessageCodec.maskBytes($0, ipv6: ipv6) } ?? Array(repeating: 0, count: width)
        var bits = 0, ended = false
        for byte in mask {
            let ones = (~byte).leadingZeroBitCount
            guard !ended || byte == 0, byte == (ones == 0 ? 0 : UInt8.max << (8 - ones)) else { return nil }
            bits += ones; ended = ones < 8
        }
        prefix = bits
    }
}

public struct RouteSequence: Sendable {
    private var value: Int32 = 0
    public init() {}
    public mutating func next() throws -> Int32 {
        guard value < Int32.max else { throw DaemonFailure.routeExhausted }
        value += 1; return value
    }
}
