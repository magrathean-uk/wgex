// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct ResolverIsolationTests {
    @Test(.enabled(if: geteuid() != 0))
    func `socket broker refuses an unprivileged caller before creating sockets`() {
        #expect(throws: DaemonFailure.hostSystem(EPERM)) { _ = try ResolverSocket.make(family: AF_INET, type: SOCK_DGRAM) }
    }

    @Test
    func `broker receive respects the lookup deadline and refuses missing rights`() throws {
        var pair: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
        defer { close(pair[0]); close(pair[1]) }
        var rights = ResolverSocket.Rights(), byte: UInt8 = 0
        withUnsafeMutablePointer(to: &byte) { bytePointer in
            var vector = iovec(iov_base: bytePointer, iov_len: 1)
            withUnsafeMutablePointer(to: &vector) { vectorPointer in
                withUnsafeMutablePointer(to: &rights) { rightsPointer in
                    var message = msghdr()
                    message.msg_iov = vectorPointer; message.msg_iovlen = 1
                    message.msg_control = UnsafeMutableRawPointer(rightsPointer)
                    message.msg_controllen = socklen_t(MemoryLayout<ResolverSocket.Rights>.size) // spellchecker:disable-line
                    #expect(throws: DaemonFailure.hostSystem(ETIMEDOUT)) {
                        _ = try ResolverSocket.receive(pair[0], message: &message, rights: rightsPointer, deadline: .now)
                    }
                    let began = ContinuousClock.now
                    #expect(throws: DaemonFailure.hostSystem(ETIMEDOUT)) {
                        _ = try ResolverSocket.receive(
                            pair[0], message: &message, rights: rightsPointer, deadline: .now + .milliseconds(20),
                        )
                    }
                    #expect(began.duration(to: .now) < .seconds(1))
                    #expect(send(pair[1], bytePointer, 1, 0) == 1)
                    // The pre-filled level/type must not make an empty control message look like SCM_RIGHTS.
                    #expect(throws: DaemonFailure.hostSystem(EIO)) {
                        _ = try ResolverSocket.receive(pair[0], message: &message, rights: rightsPointer, deadline: .now + .seconds(1))
                    }
                }
            }
        }
    }

    @Test
    func `broker closes a received descriptor when the payload guard fails`() throws {
        var pair: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0)
        defer { close(pair[0]); close(pair[1]) }
        // The transferred descriptor is one end of a private stream pair. Once the only other copy of that end is
        // closed, EOF on the peer proves the broker closed what it received, whatever number the kernel reuses.
        var carried: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &carried) == 0)
        var carriedEndOpen = true
        defer {
            if carriedEndOpen {
                close(carried[0])
            }
            close(carried[1])
        }
        try #require(fcntl(carried[1], F_SETFL, O_NONBLOCK) == 0)
        var rights = ResolverSocket.Rights(), bytes: UInt16 = 0
        withUnsafeMutablePointer(to: &bytes) { bytePointer in
            var vector = iovec(iov_base: bytePointer, iov_len: 2)
            withUnsafeMutablePointer(to: &vector) { vectorPointer in
                withUnsafeMutablePointer(to: &rights) { rightsPointer in
                    rightsPointer.pointee.descriptor = carried[0]
                    var message = msghdr()
                    message.msg_iov = vectorPointer; message.msg_iovlen = 1
                    message.msg_control = UnsafeMutableRawPointer(rightsPointer)
                    message.msg_controllen = 16 // spellchecker:disable-line
                    #expect(sendmsg(pair[1], &message, 0) == 2)
                    close(carried[0]); carriedEndOpen = false // only the in-flight and received copies remain
                    var probe: UInt8 = 0
                    #expect(read(carried[1], &probe, 1) == -1 && errno == EAGAIN) // still held by the in-flight copy
                    rightsPointer.pointee.descriptor = -1
                    // receive expects one payload byte; MSG_TRUNC/length validation rejects this two-byte datagram.
                    #expect(throws: DaemonFailure.hostSystem(EIO)) {
                        _ = try ResolverSocket.receive(pair[0], message: &message, rights: rightsPointer, deadline: .now + .seconds(1))
                    }
                    #expect(rightsPointer.pointee.descriptor >= 0)
                    // EOF (0) rather than EAGAIN means no open copy of the carried end is left, so the broker closed it.
                    #expect(read(carried[1], &probe, 1) == 0)
                }
            }
        }
    }

    @Test
    func `broker kills a stalled child before reaping`() throws {
        var pid: pid_t = 0
        let executable = strdup("/bin/sleep"), argument = strdup("30")
        defer { free(executable); free(argument) }
        var arguments = [executable, argument, nil]
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        try #require(posix_spawn(&pid, "/bin/sleep", nil, nil, &arguments, &environment) == 0)
        let began = ContinuousClock.now
        ResolverSocket.reap(pid)
        #expect(began.duration(to: .now) < .seconds(1))
        var status: Int32 = 0
        #expect(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD)
    }

    @Test
    func `DNS compression loops truncation and unrelated answers are bounded`() throws {
        let query = try UnderlayDNSCodec.query(host: "fixture.example.test", type: 1, id: 7)
        var response = query; response[2] = 0x81; response[3] = 0x80; response[7] = 1
        let address: [UInt8] = [0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]
        let cycle = response + [0xC0, UInt8(query.count)] + address
        #expect(throws: (any Error).self) { _ = try UnderlayDNSCodec.answer(cycle, query: query) }
        let other = try Array(UnderlayDNSCodec.query(host: "other.example.test", type: 1, id: 7).dropFirst(12).dropLast(4))
        #expect(try UnderlayDNSCodec.answer(response + other + address, query: query).addresses.isEmpty)
        for count in 0 ..< query.count {
            #expect(throws: (any Error).self) { _ = try UnderlayDNSCodec.answer(Array(response.prefix(count)), query: query) }
        }
        response[2] |= 2
        #expect(try UnderlayDNSCodec.answer(response, query: query).truncated)
    }

    @Test
    func `CNAME answers respect the shortest lifetime in the accepted chain`() throws {
        let query = try UnderlayDNSCodec.query(host: "fixture.example.test", type: 1, id: 7)
        let alias = try Array(UnderlayDNSCodec.query(host: "alias.example.test", type: 1, id: 7).dropFirst(12).dropLast(4))
        var response = query; response[2] = 0x81; response[3] = 0x80; response[7] = 2
        response += [0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 3, 0, UInt8(alias.count)] + alias
        response += alias + [0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]
        let answer = try UnderlayDNSCodec.answer(response, query: query)
        #expect(answer.addresses == ["192.0.2.7"])
        #expect(answer.ttl == 3)
    }

    @Test
    func `DNS query and reply validate transaction question and address records`() throws {
        let query = try UnderlayDNSCodec.query(host: "fixture.example.test", type: 1, id: 7)
        var response = query
        response[2] = 0x81; response[3] = 0x80; response[7] = 1
        response += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]
        let answer = try UnderlayDNSCodec.answer(response, query: query)
        #expect(answer.addresses == ["192.0.2.7"] && answer.ttl == 60)
        response[1] = 8
        #expect(throws: (any Error).self) { _ = try UnderlayDNSCodec.answer(response, query: query) }
    }

    @Test
    func `underlay DNS pass requires both root uid and the isolated resolver gid`() throws {
        let context = try PFContext(underlay: PFInterface("en0"), resolvers: [PFAddress("192.0.2.53")], consoleUID: 501)
        let text = try PacketFilterRenderer.render(phase: .connecting, modifiers: PFModifiers(), context: context)
        let passes = text.split(separator: "\n").filter { $0.hasPrefix("pass ") && $0.contains("port 53") }
        #expect(passes.count == 2)
        #expect(passes.allSatisfy { $0.contains("user 0 group = \(ResolverThreadIdentity.gid)") })
    }
}
