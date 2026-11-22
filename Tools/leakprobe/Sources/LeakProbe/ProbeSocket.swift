// SPDX-License-Identifier: MIT

import Darwin
import Foundation

package struct ProbeAddress: Sendable {
    package var storage: sockaddr_storage
    package let length: socklen_t

    package init(host: String, port: UInt16, type: Int32) throws {
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = type
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let resolved = result else {
            throw ProbeError.configuration("numeric socket address")
        }
        defer { freeaddrinfo(resolved) }
        guard resolved.pointee.ai_addrlen <= MemoryLayout<sockaddr_storage>.size, let pointer = resolved.pointee.ai_addr else {
            throw ProbeError.configuration("socket address length")
        }
        storage = sockaddr_storage(); length = resolved.pointee.ai_addrlen
        withUnsafeMutableBytes(of: &storage) { destination in
            destination.copyBytes(from: UnsafeRawBufferPointer(start: pointer, count: Int(length)))
        }
    }

    package func withAddress<T>(_ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T) rethrows -> T {
        var copy = storage
        return try withUnsafePointer(to: &copy) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { try body($0, length) }
        }
    }
}

/// Descriptor ownership is immutable; only the owning instance closes it.
package final class ProbeSocket: Sendable {
    package let descriptor: Int32

    package init(address: ProbeAddress, type: Int32) throws {
        descriptor = Darwin.socket(Int32(address.storage.ss_family), type, 0)
        guard descriptor >= 0 else { throw ProbeError.socket(errno) }
        var enabled: Int32 = 1
        _ = setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        if address.storage.ss_family == sa_family_t(AF_INET6) {
            _ = setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, socklen_t(MemoryLayout<Int32>.size))
        }
        guard fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else { throw ProbeError.socket(errno) }
    }

    package init(accepted: Int32) {
        descriptor = accepted
        _ = fcntl(descriptor, F_SETFL, O_NONBLOCK)
        var enabled: Int32 = 1
        _ = setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
    }

    deinit { Darwin.close(descriptor) }

    package func bind(_ address: ProbeAddress, tcp: Bool) throws -> UInt16 {
        guard address.withAddress({ Darwin.bind(descriptor, $0, $1) }) == 0 else { throw ProbeError.socket(errno) }
        if tcp, Darwin.listen(descriptor, 32) != 0 {
            throw ProbeError.socket(errno)
        }
        var local = sockaddr_storage(), length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let status = withUnsafeMutablePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        guard status == 0 else { throw ProbeError.socket(errno) }
        let family = local.ss_family
        return withUnsafePointer(to: &local) { pointer in
            if family == sa_family_t(AF_INET6) {
                pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
            } else {
                pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
            }
        }
    }

    package func wait(_ events: Int16, milliseconds: Int32 = 100) -> Bool {
        var descriptor = pollfd(fd: descriptor, events: events, revents: 0)
        return poll(&descriptor, 1, milliseconds) > 0 && descriptor.revents & events != 0
    }

    package func send(_ data: Data, to address: ProbeAddress, tcp: Bool, timeoutMilliseconds: Int32 = 100) throws {
        if !tcp {
            let count = address.withAddress { pointer, length in
                data.withUnsafeBytes { sendto(descriptor, $0.baseAddress, $0.count, 0, pointer, length) }
            }
            guard count == data.count else { throw ProbeError.socket(errno) }
            return
        }
        let status = address.withAddress { Darwin.connect(descriptor, $0, $1) }
        guard status == 0 || (errno == EINPROGRESS && wait(Int16(POLLOUT), milliseconds: timeoutMilliseconds))
        else { throw ProbeError.socket(errno) }
        var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw ProbeError.socket(error) }
        var offset = 0
        let end = ProcessInfo.processInfo.systemUptime + Double(timeoutMilliseconds) / 1000
        while offset < data.count, ProcessInfo.processInfo.systemUptime < end {
            let count = data.withUnsafeBytes { bytes in
                Darwin.send(descriptor, bytes.baseAddress?.advanced(by: offset), bytes.count - offset, 0)
            }
            if count > 0 {
                offset += count
            } else if errno == EAGAIN || errno == EINTR {
                _ = wait(Int16(POLLOUT), milliseconds: 10)
            } else {
                throw ProbeError.socket(errno)
            }
        }
        guard offset == data.count else { throw ProbeError.socket(ETIMEDOUT) }
    }
}
