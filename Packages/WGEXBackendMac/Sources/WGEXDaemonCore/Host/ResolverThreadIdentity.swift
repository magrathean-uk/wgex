// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXDaemonProtocol

/// Private process GID used only by the disposable resolver socket broker.
/// No directory-service account or host group is created. A real group using this GID causes refusal.
public struct ResolverThreadIdentity: Sendable {
    /// ASCII WGEX, below INT32_MAX; deliberately outside allocated system/user group ranges.
    public static let gid: UInt32 = 0x5747_4558
}

/// Darwin marks fork unavailable to Swift because Foundation/runtime work in a fork child can deadlock.
/// This broker's child does only the async-signal-safe libc calls below, using memory prepared before fork.
@_silgen_name("fork")
private func resolverFork() -> pid_t

/// pf reads the socket's saved process credentials, not pthread_setugid_np's thread credentials.
/// A child sets its real/effective GID before socket creation, transfers the fd, then exits.
/// No DNS, Swift allocation, Foundation, logging, locks or daemon work runs in the child.
package enum ResolverSocket {
    package struct Rights {
        package var header = cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS)
        package var descriptor: Int32 = -1
    }

    package static func make(
        family: Int32, type: Int32, deadline: ContinuousClock.Instant = .now + .seconds(8),
    ) throws -> Int32 {
        guard geteuid() == 0, getgrgid(ResolverThreadIdentity.gid) == nil else { throw DaemonFailure.hostSystem(EPERM) }
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0 else { throw DaemonFailure.hostSystem(errno) }
        let parent = pair[0], child = pair[1]
        defer { close(parent); close(child) }
        let resolverGID = ResolverThreadIdentity.gid
        var byte: UInt8 = 0
        var rights = Rights()
        return try withUnsafeMutablePointer(to: &byte) { bytePointer in
            var vector = iovec(iov_base: bytePointer, iov_len: 1)
            return try withUnsafeMutablePointer(to: &vector) { vectorPointer in
                try withUnsafeMutablePointer(to: &rights) { rightsPointer in
                    var message = msghdr()
                    message.msg_iov = vectorPointer; message.msg_iovlen = 1
                    message.msg_control = UnsafeMutableRawPointer(rightsPointer)
                    message.msg_controllen = socklen_t(MemoryLayout<Rights>.size) // spellchecker:disable-line
                    return try withUnsafeMutablePointer(to: &message) { messagePointer in
                        let pid = resolverFork()
                        if pid == 0 {
                            // Keep this branch allocation-free. setgid is process-local to this disposable child.
                            close(parent)
                            if setgid(resolverGID) != 0 {
                                _exit(1)
                            }
                            let fd = socket(family, type, 0)
                            if fd < 0 {
                                _exit(1)
                            }
                            rightsPointer.pointee.descriptor = fd
                            let sent = sendmsg(child, messagePointer, MSG_DONTWAIT)
                            close(fd); close(child)
                            _exit(sent == 1 ? 0 : 1)
                        }
                        guard pid > 0 else { throw DaemonFailure.hostSystem(errno) }
                        // The broker has no work after transfer. Kill before reaping, including failed/expired receives.
                        defer { reap(pid) }
                        return try receive(parent, message: messagePointer, rights: rightsPointer, deadline: deadline)
                    }
                }
            }
        }
    }

    /// Only the unreaped child PID returned by this broker's fork may reach here.
    package static func reap(_ pid: pid_t) {
        kill(pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0, errno == EINTR {}
    }

    package static func receive(
        _ parent: Int32, message: UnsafeMutablePointer<msghdr>, rights: UnsafeMutablePointer<Rights>,
        deadline: ContinuousClock.Instant,
    ) throws -> Int32 {
        let remaining = ContinuousClock.now.duration(to: deadline).components
        let milliseconds = remaining.seconds * 1000 + remaining.attoseconds / 1_000_000_000_000_000
        guard milliseconds > 0 else { throw DaemonFailure.hostSystem(ETIMEDOUT) }
        var item = pollfd(fd: parent, events: Int16(POLLIN), revents: 0)
        guard poll(&item, 1, Int32(min(milliseconds, Int64(Int32.max)))) > 0,
              item.revents & Int16(POLLIN) != 0 else { throw DaemonFailure.hostSystem(ETIMEDOUT) }
        let received = recvmsg(parent, message, MSG_DONTWAIT)
        // Darwin requires CMSG_LEN(sizeof(Int32)) = 16 bytes for the header and one descriptor.
        guard received == 1,
              message.pointee.msg_flags & MSG_CTRUNC == 0,
              message.pointee.msg_controllen >= 16, // spellchecker:disable-line
              rights.pointee.header.cmsg_len == 16,
              rights.pointee.header.cmsg_level == SOL_SOCKET,
              rights.pointee.header.cmsg_type == SCM_RIGHTS,
              rights.pointee.descriptor >= 0
        else {
            if rights.pointee.descriptor >= 0 {
                close(rights.pointee.descriptor)
            }
            throw DaemonFailure.hostSystem(EIO)
        }
        let fd = rights.pointee.descriptor
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { close(fd); throw DaemonFailure.hostSystem(errno) }
        return fd
    }
}
