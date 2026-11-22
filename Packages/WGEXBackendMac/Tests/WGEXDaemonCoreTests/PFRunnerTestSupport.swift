// SPDX-License-Identifier: MIT

import Foundation
import Testing
@testable import WGEXDaemonCore

package struct PFFixture {
    /// Behaviour tests allow scheduler/launch latency; this is a finite hang bound, not an assertion.
    package static let processDeadline: TimeInterval = 120

    package let directory: URL
    package let system: PFProcessExecutor

    package init() throws {
        // Foundation's default ignores routed TMPDIR on macOS; prefer the process environment.
        let temporaryDirectory = ProcessInfo.processInfo.environment["TMPDIR"]
            .flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0, isDirectory: true) : nil }
            ?? FileManager.default.temporaryDirectory
        directory = temporaryDirectory.appendingPathComponent("wgex-fake-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("replies"), withIntermediateDirectories: true)
        let source = try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
            .appendingPathComponent("fake-pfctl")
        let executable = directory.appendingPathComponent("fake-pfctl")
        try FileManager.default.copyItem(at: source, to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        system = PFProcessExecutor(executable: executable)
    }

    package var runner: PFCtl {
        PFCtl(system: system, deadline: Self.processDeadline)
    }

    package func cleanup() {
        try? FileManager.default.removeItem(at: directory)
    }

    package func reply(_ number: Int, _ suffix: String, _ value: String) throws {
        try Data(value.utf8).write(to: directory.appendingPathComponent("replies/\(number).\(suffix)"))
    }

    package func recorded(_ number: Int, _ name: String) throws -> String {
        try String(contentsOf: directory.appendingPathComponent("call-\(number)/\(name)"), encoding: .utf8)
    }

    package var count: Int {
        (try? String(contentsOf: directory.appendingPathComponent("count"), encoding: .utf8))
            .flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? 0
    }

    /// Keep the write-ahead callback open while looking for evidence of premature execution.
    package func expectNoExecutionDuringCallback() {
        let countPath = directory.appendingPathComponent("count").path
        let callPath = directory.appendingPathComponent("call-1").path
        let end = ProcessInfo.processInfo.systemUptime + 1
        var sawCount = false, sawCall = false
        while true {
            sawCount = sawCount || FileManager.default.fileExists(atPath: countPath)
            sawCall = sawCall || FileManager.default.fileExists(atPath: callPath)
            if sawCount && sawCall || ProcessInfo.processInfo.systemUptime >= end {
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        #expect(!sawCount, "fixture count appeared before the callback returned")
        #expect(!sawCall, "fixture call-1 appeared before the callback returned")
    }
}
