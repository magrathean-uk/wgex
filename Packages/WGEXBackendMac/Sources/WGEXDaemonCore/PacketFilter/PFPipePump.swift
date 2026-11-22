// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import WGEXDaemonProtocol

/// Bounded nonblocking pipe I/O, with no reader task left behind on a deadline.
package struct PFPipePump {
    private let writer: FileHandle
    private let readers: [FileHandle]
    private let input: Data
    private var eof = [false, false]
    private var offset = 0
    private var inputClosed = false
    private var buffer = [UInt8](repeating: 0, count: 16384)
    package private(set) var output = [Data(), Data()]
    package var finished: Bool {
        eof.allSatisfy(\.self)
    }

    package init(writer: FileHandle, readers: [FileHandle], input: Data) throws {
        self.writer = writer; self.readers = readers; self.input = input
        for handle in [writer] + readers {
            let descriptor = handle.fileDescriptor
            guard fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) != -1 else {
                throw DaemonFailure.pfProcess(errno)
            }
        }
        // A child may reject stdin early; do not let SIGPIPE terminate the daemon.
        guard fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else { throw DaemonFailure.pfProcess(errno) }
    }

    /// Blocks for descriptor readiness, bounded by the same monotonic process deadline.
    package func wait(
        until deadline: TimeInterval,
        now: @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
    ) throws {
        var descriptors = readers.indices.filter { !eof[$0] }.map {
            pollfd(fd: readers[$0].fileDescriptor, events: Int16(POLLIN), revents: 0)
        }
        if !inputClosed {
            descriptors.append(pollfd(fd: writer.fileDescriptor, events: Int16(POLLOUT), revents: 0))
        }
        let remaining = deadline - now()
        guard remaining > 0 else { throw DaemonFailure.pfDeadline }
        let timeout = Int32(min(remaining * 1000 + 1, Double(Int32.max)))
        let count = poll(&descriptors, nfds_t(descriptors.count), timeout)
        guard count >= 0 || errno == EINTR else { throw DaemonFailure.pfProcess(errno) }
        if count == 0 {
            throw DaemonFailure.pfDeadline
        }
    }

    package mutating func step() throws {
        try writeInput()
        for index in readers.indices where !eof[index] {
            try readOutput(index)
        }
    }

    private mutating func writeInput() throws {
        guard !inputClosed else { return }
        let count = input.withUnsafeBytes { bytes -> Int in
            guard offset < bytes.count, let base = bytes.baseAddress else { return 0 }
            return Darwin.write(writer.fileDescriptor, base.advanced(by: offset), min(bytes.count - offset, 16384))
        }
        if count > 0 {
            offset += count
        }
        if offset == input.count || (count < 0 && errno != EAGAIN && errno != EINTR) {
            try writer.close(); inputClosed = true
        }
    }

    private mutating func readOutput(_ index: Int) throws {
        let count = Darwin.read(readers[index].fileDescriptor, &buffer, buffer.count)
        if count > 0 {
            output[index].append(contentsOf: buffer.prefix(count))
            guard output[index].count <= 4 * 1024 * 1024 else { throw DaemonFailure.pfVerification }
        } else if count == 0 {
            eof[index] = true
        } else if errno != EAGAIN, errno != EINTR {
            throw DaemonFailure.pfProcess(errno)
        }
    }
}
