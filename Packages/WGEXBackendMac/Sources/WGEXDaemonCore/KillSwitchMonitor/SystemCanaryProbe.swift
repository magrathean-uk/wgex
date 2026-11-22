// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Sends the interface-bound packet used to verify packet-filter evaluation.
public enum SystemCanaryProbe {
    /// Sends one bound canary datagram; the pf counter determines success.
    public static func send() throws {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            let underlay = try SystemUnderlayMonitor.read().snapshot
            let family = PFCanaryFamily.choose(underlay)
            var index = underlay.v4 ?? underlay.v6 ?? if_nametoindex("lo0")
            guard index > 0 else { throw DaemonFailure.pfUnavailable }
            let ipv6 = family == .ipv6
            let fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)
            guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
            defer { close(fd) }
            guard setsockopt(
                fd,
                ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                ipv6 ? IPV6_BOUND_IF : IP_BOUND_IF,
                &index,
                socklen_t(MemoryLayout.size(ofValue: index)),
            ) == 0 else { throw DaemonFailure.hostSystem(errno) }
            let count = try ipv6 ? sendIPv6(fd, target: family.address) : sendIPv4(fd, target: family.address)
            // A blocking canary rule may cause EACCES; the rule counter remains the source of truth.
            guard count == 1 || errno == EACCES || errno == EPERM else { throw DaemonFailure.hostSystem(errno) }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    #if os(macOS)
        private static func sendIPv4(_ fd: Int32, target: String) throws -> Int {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = UInt8(AF_INET)
            address.sin_port = UInt16(9).bigEndian
            guard inet_pton(AF_INET, target, &address.sin_addr) == 1 else { throw DaemonFailure.pfUnavailable }
            return withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, [UInt8(0)], 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        private static func sendIPv6(_ fd: Int32, target: String) throws -> Int {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); address.sin6_family = UInt8(AF_INET6)
            address.sin6_port = UInt16(9).bigEndian
            guard inet_pton(AF_INET6, target, &address.sin6_addr) == 1 else { throw DaemonFailure.pfUnavailable }
            return withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, [UInt8(0)], 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
    #endif
}
