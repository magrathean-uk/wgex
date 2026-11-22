// SPDX-License-Identifier: MIT

import Darwin
import Foundation
import Synchronization
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Uptime stays fixed through launch. Only an observed, owned fixture child advances it.
private final class PFControlledChild: Sendable {
    let fixture: PFFixture
    private let control: FileHandle
    private let state = Mutex((pid: Int32(0), ready: false, released: false))

    init() throws {
        fixture = try PFFixture()
        let path = fixture.directory.appendingPathComponent("replies/1.control").path
        guard mkfifo(path, 0o600) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        let descriptor = Darwin.open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        control = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    func record(_ pid: Int32) {
        state.withLock { $0.pid = pid }
        #expect(Self.isOwned(pid))
    }

    private static func isOwned(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var query: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        return sysctl(&query, u_int(query.count), &info, &size, nil, 0) == 0
            && size == MemoryLayout<kinfo_proc>.size && info.kp_eproc.e_ppid == getpid()
    }

    func now(expire: Bool) -> TimeInterval {
        state.withLock { value in
            let ready = try? fixture.recorded(1, "ready")
            if ready == "\(value.pid) \(getpid())\n", Self.isOwned(value.pid) {
                value.ready = true
                // Absolute end is 1000 + 600; launch consumed no virtual time.
                if expire {
                    return 1601
                }
                if !value.released {
                    // Readiness releases successful completion; no sleep or scheduler-speed assertion.
                    do { try control.write(contentsOf: Data("complete\n".utf8)); value.released = true }
                    catch { Issue.record(error) }
                }
            }
            return 1000
        }
    }

    func assertReaped() throws {
        let value = state.withLock { $0 }
        #expect(value.ready)
        // Independent cleanup expiration is a failure, never evidence of the executor reaping its child.
        #expect(!FileManager.default.fileExists(atPath: fixture.directory.appendingPathComponent("call-1/watchdog").path))
        let pid = try #require(value.pid > 0 ? value.pid : nil)
        let result = Darwin.kill(pid, 0), code = errno
        #expect(result == -1)
        #expect(code == ESRCH)
    }

    func cleanup() {
        let pid = state.withLock { $0.pid }
        // A broken executor must not leave our controlled child behind. Check kernel parentage again.
        if Self.isOwned(pid) {
            Darwin.kill(pid, SIGKILL)
            var status: Int32 = 0
            let end = ProcessInfo.processInfo.systemUptime + PFFixture.processDeadline
            var result: pid_t
            repeat {
                result = waitpid(pid, &status, WNOHANG)
                if result != 0 {
                    break
                }
                usleep(10000) // Cleanup polling only; never used to decide the deadline assertion.
            } while ProcessInfo.processInfo.systemUptime < end
            #expect(result != 0, "owned child cleanup exceeded its independent 120-second bound")
        }
        try? control.close()
        fixture.cleanup()
    }
}

@Suite(.timeLimit(.minutes(15)))
private struct PFRunnerDeadlineTests {
    @Test(arguments: [false, true])
    func `observed child completes before deadline or is killed and reaped at controlled expiration`(expire: Bool) async throws {
        let child = try PFControlledChild(); defer { child.cleanup() }
        let system = PFProcessExecutor(executable: child.fixture.system.executable, now: { child.now(expire: expire) })
        if expire {
            await #expect(throws: DaemonFailure.pfDeadline) {
                try await system.enable(deadline: 600) { child.record($0) }
            }
        } else {
            let result = try await system.enable(deadline: 600) { child.record($0) }
            #expect(result.status == 0)
            #expect(result.stdout == "ready\n")
            #expect(result.stderr == PFTranscripts.preamble)
        }
        try child.assertReaped()
        #expect(child.fixture.count == 1)
        #expect(try child.fixture.recorded(1, "argv") == "-E\n")
    }
}
