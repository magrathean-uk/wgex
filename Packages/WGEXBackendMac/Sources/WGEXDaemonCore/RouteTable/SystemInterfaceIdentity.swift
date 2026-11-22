// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol

/// Reads interface identities for the ownership fences: name and index, the link-layer address, and for a utun this
/// process's descriptor (M1-18). The kernel's ifi_lastchange is not read: it is not an identity token.
public struct SystemInterfaceIdentity: InterfaceIdentityReading {
    private let descriptors: TunnelDescriptorTable
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init(descriptors: TunnelDescriptorTable = .process) {
        self.descriptors = descriptors
    }

    /// Reads the current kernel identity for the named interface.
    public func identity(named name: String) async throws -> TunnelIdentity? {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            var link: (found: Bool, address: String?) = (false, nil)
            try Self.forEachAddress(named: name) { address in
                guard address.pointee.sa_family == UInt8(AF_LINK) else { return }
                link = (true, Self.linkAddress(address))
            }
            let index = if_nametoindex(name)
            guard link.found, index > 0 else { return nil }
            return TunnelIdentity(
                name: name, interfaceIndex: index, descriptor: descriptors.descriptor(named: name), linkAddress: link.address,
            )
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Reads the IPv4 and IPv6 addresses currently assigned to the named interface.
    public func addresses(named name: String) async throws -> [IPAddressRange] {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            var result: [IPAddressRange] = []
            try Self.forEachAddress(named: name) { address in
                if let text = Self.text(address), let range = try? IPAddressRange(text) {
                    result.append(range)
                }
            }
            return result
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    #if os(macOS)
        private static func forEachAddress(named name: String, _ body: (UnsafeMutablePointer<sockaddr>) -> Void) throws {
            var list: UnsafeMutablePointer<ifaddrs>?
            guard getifaddrs(&list) == 0 else { throw DaemonFailure.hostSystem(errno) }
            defer { freeifaddrs(list) }
            var cursor = list
            while let item = cursor {
                defer { cursor = item.pointee.ifa_next }
                guard String(cString: item.pointee.ifa_name) == name, let address = item.pointee.ifa_addr else { continue }
                body(address)
            }
        }

        /// Lowercase colon-separated hex; nil when the interface has no link-layer address (a utun).
        private static func linkAddress(_ address: UnsafeMutablePointer<sockaddr>) -> String? {
            address.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { link in
                let length = Int(link.pointee.sdl_alen)
                guard length > 0, let offset = MemoryLayout<sockaddr_dl>.offset(of: \sockaddr_dl.sdl_data) else { return nil }
                let start = UnsafeRawPointer(link) + offset + Int(link.pointee.sdl_nlen)
                guard offset + Int(link.pointee.sdl_nlen) + length <= Int(link.pointee.sdl_len) else { return nil }
                return (0 ..< length).map { String(format: "%02x", start.load(fromByteOffset: $0, as: UInt8.self)) }
                    .joined(separator: ":")
            }
        }

        /// NUL-terminated C characters as UTF-8 text.
        package static func string(_ characters: [CChar]) -> String {
            String(decoding: characters.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }

        private static func text(_ address: UnsafeMutablePointer<sockaddr>) -> String? {
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            switch Int32(address.pointee.sa_family) {
            case AF_INET:
                return address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { inet in
                    var raw = inet.pointee.sin_addr
                    return inet_ntop(AF_INET, &raw, &buffer, socklen_t(buffer.count)).map { _ in Self.string(buffer) }
                }
            case AF_INET6:
                return address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { inet in
                    var raw = inet.pointee.sin6_addr
                    return inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)).map { _ in Self.string(buffer) }
                }
            default:
                return nil
            }
        }
    #endif
}
