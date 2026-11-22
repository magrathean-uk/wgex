// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Synchronization
import WGEXCore

/// The utun kernel-control descriptors this daemon process holds, by the generation whose engine created them (M1-18).
/// The engine factory records the descriptor once the engine reports its utun name; the identity reader reports it for
/// as long as it stays open and reports that name. Process memory only: a restarted daemon holds none, so a journalled
/// tunnel identity from an earlier launch never matches, and a descriptor number reused by a later generation's engine
/// carries that generation.
public final class TunnelDescriptorTable: Sendable {
    /// Descriptors belong to the process, so production shares one table between the engine factory and the reader.
    public static let process = TunnelDescriptorTable(probe: .system)
    private let probe: TunnelDescriptorProbe
    private let entries = Mutex<[Int32: Generation]>([:])

    package init(probe: TunnelDescriptorProbe) {
        self.probe = probe
    }

    /// Records this process's open utun descriptor reporting `name` for `generation`; nil when no descriptor does.
    /// Entries whose descriptor no longer reports any utun name are dropped.
    public func register(name: String, generation: Generation) -> TunnelDescriptor? {
        guard let fd = probe.candidates().filter({ probe.interfaceName($0) == name }).min() else { return nil }
        let probe = probe
        entries.withLock { table in
            table = table.filter { probe.interfaceName($0.key) != nil }
            table[fd] = generation
        }
        return TunnelDescriptor(fd: fd, generation: generation)
    }

    /// The recorded descriptor still open and reporting `name`, with the generation that recorded it; nil otherwise.
    public func descriptor(named name: String) -> TunnelDescriptor? {
        let table = entries.withLock { $0 }
        return table.filter { probe.interfaceName($0.key) == name }.max { $0.value < $1.value }
            .map { TunnelDescriptor(fd: $0.key, generation: $0.value) }
    }
}

/// How the table reads this process's descriptors: the open socket descriptors, and the utun name one reports.
package struct TunnelDescriptorProbe: Sendable {
    package let candidates: @Sendable () -> [Int32]
    package let interfaceName: @Sendable (Int32) -> String?
    package init(candidates: @escaping @Sendable () -> [Int32], interfaceName: @escaping @Sendable (Int32) -> String?) {
        self.candidates = candidates; self.interfaceName = interfaceName
    }

    /// Read-only calls on this process's own descriptors; nothing is opened, connected or changed.
    package static let system = TunnelDescriptorProbe(candidates: socketDescriptors, interfaceName: utunName)

    /// Socket descriptors of this process (PROC_PIDLISTFDS).
    private static func socketDescriptors() -> [Int32] {
        #if os(macOS)
            let size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nil, 0)
            guard size > 0 else { return [] }
            let stride = MemoryLayout<proc_fdinfo>.stride
            var list = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / stride + 8)
            let used = list.withUnsafeMutableBytes { proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
            guard used > 0 else { return [] }
            return list.prefix(Int(used) / stride).filter { $0.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) }.map(\.proc_fd)
        #else
            return []
        #endif
    }

    /// The utun name a kernel-control descriptor reports (UTUN_OPT_IFNAME); nil for a closed or any other descriptor.
    private static func utunName(_ fd: Int32) -> String? {
        #if os(macOS)
            var peer = sockaddr_ctl()
            var length = socklen_t(MemoryLayout<sockaddr_ctl>.size)
            let connected = withUnsafeMutablePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
            }
            guard connected == 0, peer.sc_family == UInt8(AF_SYSTEM), peer.ss_sysaddr == UInt16(AF_SYS_CONTROL) else { return nil }
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1)
            var size = socklen_t(IFNAMSIZ)
            // net/if_utun.h UTUN_OPT_IFNAME; the header is not part of the Swift Darwin module.
            let utunOptionInterfaceName: Int32 = 2
            guard getsockopt(fd, SYSPROTO_CONTROL, utunOptionInterfaceName, &name, &size) == 0, size > 0 else { return nil }
            let text = SystemInterfaceIdentity.string(name)
            return text.hasPrefix("utun") ? text : nil
        #else
            return nil
        #endif
    }
}
