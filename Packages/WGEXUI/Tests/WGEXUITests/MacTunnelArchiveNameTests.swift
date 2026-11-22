// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXUI

    @MainActor
    @Suite("M02-T08 export all entry names", .timeLimit(.minutes(1)))
    private struct MacTunnelArchiveNameTests {
        private func zeroText(_ count: Int) throws -> SecretText {
            try SecretText(bytes: SecretBytes(zeroedCount: count))
        }

        @Test func `a name longer than the zip name field is cut, bounded and cannot trap the export`() async throws {
            // One grapheme of 65,538 bytes as a .conf name: "a" plus 32,766 combining acute accents.
            let huge = "a" + String(repeating: "\u{301}", count: 32766)
            #expect(huge.count == 1)
            #expect(huge.utf8.count + ".conf".utf8.count == 65538)
            let names = MacTunnelArchive.entryNames(for: [huge, huge, "Plain"])
            #expect(names == ["1.conf", "2.conf", "Plain.conf"])
            let root = MacWorkflowTests.scratch()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let destination = root.appendingPathComponent("huge.zip")
            try await MacTunnelArchive.write(names: [huge, "Plain"], to: destination) { _ in try zeroText(8) }
            let entries = try MacImportSources.archive(Data(contentsOf: destination))
            #expect(entries.map(\.0) == ["1", "Plain"])
        }

        @Test func `long names are cut on a grapheme boundary within the byte bound`() {
            let room = MacTunnelArchive.maximumNameBytes - ".conf".utf8.count
            let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}" // one 25-byte grapheme
            let accented = "e\u{301}" // one 3-byte grapheme
            let ascii = String(repeating: "x", count: 400)
            let names = MacTunnelArchive.entryNames(for: [
                ascii, String(repeating: family, count: 40), String(repeating: accented, count: 200), "\u{4E2D}" + ascii,
            ])
            for name in names {
                #expect(name.utf8.count <= MacTunnelArchive.maximumNameBytes)
                #expect(name.hasSuffix(".conf"))
            }
            #expect(names[0].utf8.count == MacTunnelArchive.maximumNameBytes)
            // 10 whole families fit in 250 bytes (250 / 25); an eleventh would be cut mid-grapheme.
            #expect(names[1] == String(repeating: family, count: room / 25) + ".conf")
            #expect(names[2] == String(repeating: accented, count: room / 3) + ".conf")
            #expect(names[3].hasPrefix("\u{4E2D}x"))
            #expect(names[3].utf8.count <= MacTunnelArchive.maximumNameBytes)
        }

        @Test func `names that collide after the cut stay distinct`() {
            let room = MacTunnelArchive.maximumNameBytes - ".conf".utf8.count
            let shared = String(repeating: "n", count: room)
            let names = MacTunnelArchive.entryNames(for: [shared + "A", shared + "B", shared.uppercased() + "C", "1"])
            #expect(names[0] == shared + ".conf")
            #expect(Set(names.map { $0.lowercased() }).count == names.count)
            #expect(names.allSatisfy { $0.utf8.count <= MacTunnelArchive.maximumNameBytes })
        }

        @Test func `the system unzip accepts the archive and lists the flat entries`() async throws {
            let root = MacWorkflowTests.scratch()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let destination = root.appendingPathComponent("fake.zip")
            let huge = "a" + String(repeating: "\u{301}", count: 32766)
            // Fake profiles only: zeroed text stands in for configurations, so no key material exists here.
            let names = ["Home", "Work/Phone", huge, "Home", String(repeating: "L", count: 400)]
            try await MacTunnelArchive.write(names: names, to: destination) { _ in try zeroText(32) }
            if let keep = ProcessInfo.processInfo.environment["WGEX_T08_KEEP_ARCHIVE"] {
                try? FileManager.default.removeItem(atPath: keep)
                try FileManager.default.copyItem(atPath: destination.path, toPath: keep)
            }
            func run(_ tool: String, _ arguments: [String]) throws -> (Int32, String) {
                let process = Process(), pipe = Pipe()
                process.executableURL = URL(fileURLWithPath: tool); process.arguments = arguments
                process.standardOutput = pipe; process.standardError = pipe
                try process.run()
                let output = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                return (process.terminationStatus, String(decoding: output, as: UTF8.self))
            }
            #expect(try run("/usr/bin/unzip", ["-tq", destination.path]).0 == 0)
            let listing = try run("/usr/bin/zipinfo", ["-1", destination.path])
            #expect(listing.0 == 0)
            #expect(listing.1.split(separator: "\n").map(String.init) == MacTunnelArchive.entryNames(for: names))
        }
    }
#endif
