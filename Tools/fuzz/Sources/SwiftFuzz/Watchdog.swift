// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// Hang detector. A vector still running after `hangLimit` is saved as a reproducer and
/// the process exits with status 3; the 50 ms deadline itself is enforced by the driver.
package final class Watchdog: Sendable {
    package static let hangLimit: Duration = .seconds(2)

    private struct Current: Sendable {
        let name: String
        let bytes: [UInt8]
        let started: ContinuousClock.Instant
    }

    private let current = Mutex<Current?>(nil)
    private let reproducers: URL

    package init(reproducers: URL) {
        self.reproducers = reproducers
    }

    /// `name` is the reproducer basename, `<target>-hang-<vector>`.
    package func begin(name: String, bytes: [UInt8]) {
        current.withLock { $0 = Current(name: name, bytes: bytes, started: .now) }
    }

    package func end() {
        current.withLock { $0 = nil }
    }

    package func start() {
        let thread = Thread { [self] in
            while true {
                Thread.sleep(forTimeInterval: 0.01)
                let hung = current.withLock { state -> Current? in
                    guard let state, state.started.duration(to: .now) > Self.hangLimit else { return nil }
                    return state
                }
                guard let hung else { continue }
                try? Data(hung.bytes).write(to: reproducers.appendingPathComponent("\(hung.name).bin"))
                FileHandle.standardError.write(Data("hang: \(hung.name)\n".utf8))
                exit(3)
            }
        }
        thread.stackSize = 1 << 20
        thread.start()
    }
}

/// The vector under test is mirrored to `pending.bin` and `pending.name` so `run.sh` can
/// save it as a reproducer when the process dies from a signal (a crash in the target).
package struct PendingVector: Sendable {
    private let bytesURL: URL
    private let nameURL: URL

    package init(directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        bytesURL = directory.appendingPathComponent("pending.bin")
        nameURL = directory.appendingPathComponent("pending.name")
    }

    package func record(name: String, bytes: [UInt8]) throws {
        try Data(bytes).write(to: bytesURL)
        try Data(name.utf8).write(to: nameURL)
    }

    package func clear() {
        try? FileManager.default.removeItem(at: bytesURL)
        try? FileManager.default.removeItem(at: nameURL)
    }
}
