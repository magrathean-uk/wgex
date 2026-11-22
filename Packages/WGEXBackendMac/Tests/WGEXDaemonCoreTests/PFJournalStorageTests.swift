// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

private struct PFJournalStorageTests {
    @Test
    func `file token journal round trips and rejects malformed token`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-journal-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = PFFileTokenJournal(url: directory.appendingPathComponent("pf.json"))
        #expect(try journal.readToken() == nil)
        try journal.writeToken("98765")
        #expect(try journal.readToken() == "98765")
        #expect(try FileManager.default.attributesOfItem(atPath: journal.url.path)[.posixPermissions] as? Int == 0o600)
        #expect(throws: DaemonFailure.pfToken) { try journal.writeToken("-X all") }
        try journal.writeToken(nil)
        #expect(try journal.readToken() == nil)
    }

    @Test
    func `journal never follows target symlinks`() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-link-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        try Data("untouched".utf8).write(to: target)
        let link = directory.appendingPathComponent("pf.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let journal = PFFileTokenJournal(url: link)
        #expect(throws: (any Error).self) { try journal.readToken() }
        try journal.writeToken("99")
        #expect(try journal.readToken() == "99")
        #expect(try String(contentsOf: target, encoding: .utf8) == "untouched")
    }
}
