// SPDX-License-Identifier: MIT

import Foundation
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// macOS 26.6.2 guest captures; fixtures are resolved independently of the test working directory.
package enum PFTranscripts {
    package static let preamble = "No ALTQ support in kernel\nALTQ related functions disabled\n"
    package static let capturedPID: Int32 = 12060
    package static let capturedToken = "6419684541550600056"

    /// Ownership and elapsed age varied by lifecycle fakes; layout comes from the capture.
    package struct Reference {
        package let pid: Int32
        package var process = "pfctl"
        package let token: String
        package var age = 0
    }

    package static func read(_ name: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("Tests/Fixtures/pfctl/macos26/\(name).txt"), encoding: .utf8)
    }

    /// Captures merge stderr; pfctl writes ALTQ warnings to stderr, never to the rules stream.
    package static func stdout(_ name: String) throws -> String {
        try read(name).replacingOccurrences(of: preamble, with: "")
    }

    package static func enabledInfo(_ enabled: Bool) throws -> String {
        let text = try stdout("info")
        return enabled ? text.replacingOccurrences(of: "Status: Disabled", with: "Status: Enabled") : text
    }

    /// Retain the real table and command spelling while substituting the fake's journalled token.
    package static func read(_ name: String, token: String) throws -> String {
        try read(name).replacingOccurrences(of: capturedToken, with: token)
    }

    /// Render mutable ownership in the captured TOKENS table; an empty set uses its real empty reply.
    package static func references(_ rows: [Reference]) throws -> String {
        guard !rows.isEmpty else { return try stdout("references-before") }
        let table = try stdout("references-with-token")
        guard let row = table.split(separator: "\n")
            .first(where: { $0.split(whereSeparator: \.isWhitespace).first.map(String.init) == String(capturedPID) })
        else { throw DaemonFailure.pfVerification }
        let template = row.replacingOccurrences(of: String(capturedPID), with: "<pid>")
            .replacingOccurrences(of: "pfctl", with: "<process>")
            .replacingOccurrences(of: capturedToken, with: "<token>")
            .replacingOccurrences(of: "0 days 00:00:00", with: "<age>")
        let rendered = rows.map { row in
            let elapsed = String(format: "%02d:%02d:%02d", row.age / 3600 % 24, row.age / 60 % 60, row.age % 60)
            return template.replacingOccurrences(of: "<pid>", with: String(row.pid))
                .replacingOccurrences(of: "<process>", with: row.process)
                .replacingOccurrences(of: "<token>", with: row.token)
                .replacingOccurrences(of: "<age>", with: "\(row.age / 86400) days \(elapsed)")
        }.joined(separator: "\n")
        return table.replacingOccurrences(of: String(row), with: rendered)
    }
}

private struct PFTranscriptTests {
    @Test
    func `reference rows preserve the captured table while varying ownership and age`() throws {
        let text = try PFTranscripts.references([
            .init(pid: 123, token: "99"),
            .init(pid: 456, process: "a process with spaces", token: "100", age: 90061),
        ])
        #expect(text.hasPrefix("TOKENS:\nPID"))
        #expect(!text.contains(String(PFTranscripts.capturedPID)))
        #expect(!text.contains(PFTranscripts.capturedToken))
        let rows = try PacketFilterReadback.references(text)
        #expect(rows.map(\.pid) == [123, 456])
        #expect(rows.map(\.process) == ["pfctl", "a process with spaces"])
        #expect(rows.map(\.token) == ["99", "100"])
        #expect(rows.map(\.age) == [0, 90061])
        #expect(try PFTranscripts.references([]) == PFTranscripts.stdout("references-before"))
    }

    @Test
    func `captured references expose the real PID process name and elapsed timestamp`() throws {
        let row = try #require(PacketFilterReadback.references(PFTranscripts.read("references-with-token")).first)
        #expect(row.pid == PFTranscripts.capturedPID)
        #expect(row.process == "pfctl")
        #expect(row.token == PFTranscripts.capturedToken)
        #expect(row.age == 0)
    }

    @Test
    func `macOS 26 enable and reference table agree exactly`() throws {
        #expect(try PacketFilterReadback.token(PFTranscripts.read("enable")) == PFTranscripts.capturedToken)
        #expect(try PacketFilterReadback.referenceTokens(PFTranscripts.read("references-with-token")) == [PFTranscripts.capturedToken])
        for name in ["references-before", "references-after"] {
            #expect(try PacketFilterReadback.referenceTokens(PFTranscripts.read(name)).isEmpty)
        }
        #expect(try PacketFilterReadback.stockAnchorPresent(PFTranscripts.read("rules")))
        #expect(try PacketFilterReadback.matches(PFTranscripts.stdout("anchor-wgex"), rendered: ""))
    }

    @Test(arguments: [
        "enable",
        "release",
        "info",
        "references-before",
        "references-with-token",
        "references-after",
        "rules",
        "rules-verbose",
        "anchors",
        "anchor-wgex",
    ])
    func `every captured pf command has the real ALTQ preamble`(name: String) throws {
        #expect(try PFTranscripts.read(name).hasPrefix(PFTranscripts.preamble))
    }
}

package func verbosePF(_ text: String, counter: UInt64) -> String {
    text.split(separator: "\n").filter { !$0.hasPrefix("table <") }.enumerated().map { index, line in
        let value = line.contains("wgex-canary") ? counter : 0
        return "@\(index) \(line)\n  [ Evaluations: \(value) Packets: 0 Bytes: 0 States: 0 ]"
    }.joined(separator: "\n") + "\n"
}
