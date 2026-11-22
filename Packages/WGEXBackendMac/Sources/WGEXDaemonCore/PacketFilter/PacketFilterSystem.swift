// SPDX-License-Identifier: MIT

import Darwin
import Dispatch
import Foundation
import WGEXDaemonProtocol

public struct PFCommandResult: Sendable, Equatable {
    public let status: Int32
    public let stdout: String
    public let stderr: String

    public init(status: Int32 = 0, stdout: String = "", stderr: String = "") {
        self.status = status; self.stdout = stdout; self.stderr = stderr
    }
}

/// Production fixes the executable and environment; tests supply only the fixture adapter.
public protocol PacketFilterSystem: Sendable {
    /// Starts a child behind an exec gate; beforeExec must complete durably before -E can execute.
    func enable(deadline: TimeInterval, beforeExec: @escaping @Sendable (Int32) throws -> Void) async throws -> PFCommandResult
    func run(arguments: [String], input: Data, deadline: TimeInterval) async throws -> PFCommandResult
}

#if os(macOS)
    /// Package-internal process machinery, shared with the fake-executable tests.
    /// Nonblocking I/O drains both pipes and writes stdin under the same monotonic deadline.
    package struct PFProcessExecutor: PacketFilterSystem {
        package let executable: URL
        private let now: @Sendable () -> TimeInterval

        /// Tests can advance monotonic time after observing their owned child; production uses uptime.
        // swiftformat:disable:next redundantInternal
        internal init(
            executable: URL,
            now: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        ) {
            self.executable = executable; self.now = now
        }

        package func run(arguments: [String], input: Data, deadline: TimeInterval) async throws -> PFCommandResult {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global().async {
                    do { try continuation.resume(returning: execute(arguments: arguments, input: input, deadline: deadline)) }
                    catch { continuation.resume(throwing: error) }
                }
            }
        }

        package func enable(
            deadline: TimeInterval,
            beforeExec: @escaping @Sendable (Int32) throws -> Void,
        ) async throws -> PFCommandResult {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global().async {
                    do { try continuation.resume(returning: execute(
                        arguments: ["-E"],
                        input: Data([10]),
                        deadline: deadline,
                        beforeExec: beforeExec,
                    )) } catch { continuation.resume(throwing: error) }
                }
            }
        }

        private func makeProcess(arguments: [String], gated: Bool) -> Process {
            let process = Process()
            // A fixed shell builtin blocks on stdin before exec. No command text contains caller data;
            // the absolute executable and arguments are positional parameters. exec preserves the child PID.
            // Parent death closes the pipe, so read fails and pfctl never runs without a durable attempt.
            process.executableURL = !gated ? executable : URL(fileURLWithPath: "/bin/sh")
            process.arguments = !gated ? arguments :
                ["-c", "IFS= read -r gate && exec \"$@\"", "wgex-pf-enable", executable.path] + arguments
            process.environment = [:]
            return process
        }

        private func execute(
            arguments: [String],
            input: Data,
            deadline: TimeInterval,
            beforeExec: (@Sendable (Int32) throws -> Void)? = nil,
        ) throws -> PFCommandResult {
            guard deadline > 0, deadline.isFinite else { throw DaemonFailure.pfDeadline }
            let process = makeProcess(arguments: arguments, gated: beforeExec != nil)
            let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
            process.standardInput = stdin; process.standardOutput = stdout; process.standardError = stderr
            let end = now() + deadline
            try process.run(); try stdin.fileHandleForReading.close()
            try stdout.fileHandleForWriting.close(); try stderr.fileHandleForWriting.close()
            let writer = stdin.fileHandleForWriting
            let readers = [stdout.fileHandleForReading, stderr.fileHandleForReading]
            defer {
                try? writer.close()
                for reader in readers {
                    try? reader.close()
                }
            }
            let exited = DispatchSemaphore(value: 0)
            let exitSource = DispatchSource.makeProcessSource(
                identifier: process.processIdentifier, eventMask: .exit, queue: DispatchQueue.global(),
            )
            exitSource.setEventHandler { exited.signal() }; exitSource.resume()
            defer { exitSource.cancel() }
            do {
                try beforeExec?(process.processIdentifier)
                #if WGEX_LAB_BUILD
                    if executable.path == "/sbin/pfctl" {
                        DaemonDiagnostics.packetFilterSpawn(arguments)
                    }
                #endif
                var pump = try PFPipePump(writer: writer, readers: readers, input: input)
                while !pump.finished {
                    try pump.wait(until: end, now: now)
                    try pump.step()
                }
                if process.isRunning {
                    let remaining = max(0, end - now())
                    guard exited.wait(timeout: .now() + remaining) == .success else { throw DaemonFailure.pfDeadline }
                }
                process.waitUntilExit()
                return PFCommandResult(
                    status: process.terminationStatus,
                    stdout: String(decoding: pump.output[0], as: UTF8.self),
                    stderr: String(decoding: pump.output[1], as: UTF8.self),
                )
            } catch {
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
                process.waitUntilExit()
                throw error
            }
        }
    }
#endif
