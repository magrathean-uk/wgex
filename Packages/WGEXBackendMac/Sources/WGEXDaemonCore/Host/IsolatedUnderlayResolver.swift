// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Native interface-bound DNS uses sockets credentialled by a disposable child process.
/// The daemon never changes its credentials or uses the default system resolver.
public struct IsolatedUnderlayResolver: EngineResolveCalling {
    /// Constructing this port opens no socket and changes no credentials.
    public init() {}

    /// At most three supplied servers, two address families, with a two-second budget per exchange.
    public func resolve(host: String, v4: UInt32?, v6: UInt32?, resolvers: [String]) async throws -> Data {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #elseif DEBUG
                guard !HostGuard.refuseOwnerMac() else { throw DaemonFailure.hostSystem(EPERM) }
            #endif
            return try await withCheckedThrowingContinuation { continuation in
                let thread = Thread {
                    do {
                        let result = try Self.lookup(host: host, v4: v4, v6: v6, resolvers: resolvers)
                        continuation.resume(returning: result)
                    } catch { continuation.resume(throwing: DaemonFailure.hostSystem(EHOSTUNREACH)) }
                }
                thread.name = "WGEX isolated DNS"; thread.start()
            }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    #if os(macOS)
        private struct Response: Encodable { let a: [String]; let aaaa: [String]; let ttl: UInt32 }

        private static func lookup(host: String, v4: UInt32?, v6: UInt32?, resolvers: [String]) throws -> Data {
            guard !resolvers.isEmpty, (v4 ?? v6 ?? 0) > 0 else { throw DaemonFailure.hostUnboundInterfaces }
            let deadline = ContinuousClock.now + .seconds(8)
            var addresses4: [String] = []; var addresses6: [String] = []; var ttl = UInt32.max
            for type: UInt16 in [1, 28] {
                for resolver in resolvers.prefix(3) {
                    guard ContinuousClock.now < deadline else { break }
                    do {
                        let query = try UnderlayDNSCodec.query(host: host, type: type, id: UInt16.random(in: .min ... .max))
                        var answer = try UnderlayDNSCodec.answer(
                            exchange(query, resolver: resolver, v4: v4, v6: v6, tcp: false, deadline: deadline),
                            query: query,
                        )
                        if answer.truncated {
                            answer = try UnderlayDNSCodec.answer(
                                exchange(query, resolver: resolver, v4: v4, v6: v6, tcp: true, deadline: deadline),
                                query: query,
                            )
                        }
                        guard !answer.truncated else { throw DaemonFailure.hostSystem(EBADMSG) }
                        if type == 1 {
                            addresses4 = answer.addresses
                        } else {
                            addresses6 = answer.addresses
                        }
                        if !answer.addresses.isEmpty {
                            ttl = min(ttl, answer.ttl)
                        }
                        break
                    } catch { continue }
                }
            }
            guard !addresses4.isEmpty || !addresses6.isEmpty else { throw DaemonFailure.hostSystem(EHOSTUNREACH) }
            return try JSONEncoder().encode(Response(a: addresses4, aaaa: addresses6, ttl: ttl))
        }

        private static func exchange(
            _ query: [UInt8], resolver: String, v4: UInt32?, v6: UInt32?, tcp: Bool, deadline: ContinuousClock.Instant,
        ) throws -> [UInt8] {
            var hints = addrinfo(); hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
            hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM
            var address: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(resolver, "53", &hints, &address) == 0, let address else { throw DaemonFailure.hostSystem(EINVAL) }
            defer { freeaddrinfo(address) }
            let family = address.pointee.ai_family
            guard family == AF_INET || family == AF_INET6,
                  var index = family == AF_INET ? v4 : v6, index > 0 else { throw DaemonFailure.hostUnboundInterfaces }
            let fd = try ResolverSocket.make(family: family, type: tcp ? SOCK_STREAM : SOCK_DGRAM, deadline: deadline)
            defer { close(fd) }
            guard setsockopt(
                      fd,
                      family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                      family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,
                      &index,
                      socklen_t(MemoryLayout.size(ofValue: index)),
                  ) == 0,
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw DaemonFailure.hostSystem(errno) }
            var noSignal: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
                throw DaemonFailure.hostSystem(errno)
            }
            let deadline = min(deadline, ContinuousClock.now + .seconds(2))
            try connectSocket(fd, address: address.pointee, deadline: deadline)
            try sendPacket(query, fd: fd, tcp: tcp, deadline: deadline)
            return try receivePacket(fd, tcp: tcp, deadline: deadline)
        }

        private static func connectSocket(_ fd: Int32, address: addrinfo, deadline: ContinuousClock.Instant) throws {
            if connect(fd, address.ai_addr, address.ai_addrlen) != 0 {
                guard errno == EINPROGRESS else { throw DaemonFailure.hostSystem(errno) }
                try wait(fd, events: Int16(POLLOUT), deadline: deadline)
                var error: Int32 = 0; var length = socklen_t(MemoryLayout.size(ofValue: error))
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0,
                      error == 0 else { throw DaemonFailure.hostSystem(ECONNREFUSED) }
            }
        }

        private static func sendPacket(_ query: [UInt8], fd: Int32, tcp: Bool, deadline: ContinuousClock.Instant) throws {
            let packet = tcp ? [UInt8(query.count >> 8), UInt8(query.count & 255)] + query : query
            var sent = 0
            while sent < packet.count {
                try wait(fd, events: Int16(POLLOUT), deadline: deadline)
                let count = packet.withUnsafeBytes { raw in
                    send(fd, raw.baseAddress?.advanced(by: sent), packet.count - sent, 0)
                }
                if count < 0, errno == EAGAIN || errno == EINTR {
                    continue
                }
                guard count > 0, tcp || count == packet.count else { throw DaemonFailure.hostSystem(EIO) }
                sent += count
            }
        }

        private static func receivePacket(_ fd: Int32, tcp: Bool, deadline: ContinuousClock.Instant) throws -> [UInt8] {
            if tcp {
                let header = try read(fd, count: 2, deadline: deadline)
                let length = Int(header[0]) << 8 | Int(header[1])
                guard length >= 12 else { throw DaemonFailure.hostSystem(EBADMSG) }
                return try read(fd, count: length, deadline: deadline)
            }
            try wait(fd, events: Int16(POLLIN), deadline: deadline)
            var result = [UInt8](repeating: 0, count: 65535)
            let received = recv(fd, &result, result.count, 0)
            guard received >= 12 else { throw DaemonFailure.hostSystem(EBADMSG) }
            return Array(result.prefix(received))
        }

        private static func read(_ fd: Int32, count: Int, deadline: ContinuousClock.Instant) throws -> [UInt8] {
            var bytes = [UInt8](repeating: 0, count: count); var offset = 0
            while offset < count {
                try wait(fd, events: Int16(POLLIN), deadline: deadline)
                let received = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress?.advanced(by: offset), count - offset, 0) }
                if received < 0, errno == EAGAIN || errno == EINTR {
                    continue
                }
                guard received > 0 else { throw DaemonFailure.hostSystem(ECONNRESET) }; offset += received
            }
            return bytes
        }

        private static func wait(_ fd: Int32, events: Int16, deadline: ContinuousClock.Instant) throws {
            let remaining = ContinuousClock.now.duration(to: deadline).components
            let milliseconds = remaining.seconds * 1000 + remaining.attoseconds / 1_000_000_000_000_000
            guard milliseconds > 0 else { throw DaemonFailure.hostSystem(ETIMEDOUT) }
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&item, 1, Int32(min(milliseconds, 2000)))
            guard result > 0, item.revents & events != 0 else { throw DaemonFailure.hostSystem(ETIMEDOUT) }
        }
    #endif
}
