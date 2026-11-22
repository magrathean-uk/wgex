// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M07-T09 (DEC-110 item 21): a .zip of several tunnels opens the ticked review list; a one-tunnel file keeps the
    /// Review Tunnel sheet.
    @MainActor
    @Suite("M07-T09 multi-tunnel import list", .timeLimit(.minutes(1)))
    private struct MacImportSelectionTests {
        @Test func `two valid tunnels are both ticked, show their servers and Add All saves both`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = try await importZip([("Home", "ipv6-dual-stack"), ("Office", "multi-peer-split")], root: root)
            let reviews = app.importReviews
            try #require(reviews.count == 2)
            let selection = MacImportSelection()
            #expect(reviews.allSatisfy(selection.isTicked))
            #expect(selection.buttonTitle(in: reviews) == "Add All")
            #expect(MacImportSelection.endpoint(reviews[0]).contains("2001:db8::1"))
            #expect(MacImportSelection.endpoint(reviews[1]).contains("vpn.example.test"))
            await app.confirmAllImports(only: selection.ticked(in: reviews))?.value
            #expect(app.shell.profiles.count == 2)
            #expect(app.importReviews.isEmpty)
            #expect(!app.importing)
            #expect(try await app.profileStore.list().count == 2)
        }

        @Test func `an invalid entry shows why and cannot be ticked`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = try await importZip([("Home", "ipv6-dual-stack"), ("Broken", nil), ("Office", "multi-peer-split")], root: root)
            let reviews = app.importReviews
            try #require(reviews.count == 3)
            let broken = reviews[1]
            var selection = MacImportSelection()
            #expect(!broken.canImport)
            #expect(!selection.isTicked(broken))
            selection.set(broken, ticked: true)
            #expect(!selection.isTicked(broken))
            let reason = try #require(MacTunnelProblems.lines(broken.diagnostics, nameIsEmpty: broken.name.isEmpty).first)
            #expect(reason != MacStrings.readyToAdd && !reason.isEmpty)
            #expect(selection.buttonTitle(in: reviews) == "Add All")
            #expect(selection.ticked(in: reviews).count == 2)
            await app.confirmAllImports(only: selection.ticked(in: reviews))?.value
            #expect(app.shell.profiles.count == 2)
            #expect(app.importReviews.isEmpty)
            #expect(!app.importing)
        }

        @Test func `unticking changes the button to Add with the count and saves only the ticked`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = try await importZip([("Home", "ipv6-dual-stack"), ("Office", "multi-peer-split")], root: root)
            let reviews = app.importReviews
            try #require(reviews.count == 2)
            var selection = MacImportSelection()
            selection.set(reviews[1], ticked: false)
            #expect(selection.buttonTitle(in: reviews) == "Add 1")
            #expect(MacStrings.addCount(1) == "Add 1")
            selection.set(reviews[0], ticked: false)
            #expect(selection.buttonTitle(in: reviews) == "Add 0")
            #expect(selection.ticked(in: reviews).isEmpty)
            selection.set(reviews[0], ticked: true)
            #expect(selection.buttonTitle(in: reviews) == "Add 1")
            let name = reviews[0].name
            await app.confirmAllImports(only: selection.ticked(in: reviews))?.value
            #expect(app.shell.profiles.map(\.name) == [name])
            #expect(app.importReviews.isEmpty)
            #expect(!app.importing)
            #expect(try await app.profileStore.list().count == 1)
            let sheet = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacImportSheet.swift")
            #expect(sheet.contains(".disabled(ticked.isEmpty)"))
            #expect(sheet.contains("confirmAll(ticked)"))
        }

        @Test func `a one-tunnel file keeps the Review Tunnel sheet`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let zipped = try await importZip([("Home", "ipv6-dual-stack")], root: root)
            #expect(zipped.importReviews.count == 1)
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            app.importURLs([EditorFixtures.root.appendingPathComponent("conf/ipv6-dual-stack.conf")])
            #expect(app.importReviews.count == 1)
            let sheet = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacImportSheet.swift")
            #expect(sheet.contains("if reviews.count > 1 {\n                    listContent"))
            #expect(sheet.contains("} else if let review = reviews.first {\n                    reviewContent(review)"))
            let ids = Set(WGEXAccessibility.catalogue.map(\.id))
            for id in ["item", "itemTick", "itemEndpoint", "addAll"] {
                #expect(ids.contains("wgex.importReview.\(id)"))
            }
        }

        /// M07-T11 (lab run 5, M07-IMPORT-ZIP serversShown): each list row is one combined element labelled with the name
        /// alone, which hid the server; the row carries the server as its value.
        /// The server text itself is MacImportSelection.endpoint (checked in the first test above).
        @Test func `each zip list row exposes its server`() throws {
            let lines = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacImportSheet.swift")
                .split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.hasPrefix("//") }
            let item = try #require(lines.firstIndex(of: #".wgexAX(.importReview, "item", label: review.name, item: String(index))"#))
            #expect(lines[item - 2] == ".accessibilityElement(children: .combine)")
            #expect(lines[item - 1] == ".accessibilityValue(endpoint)", "the combined row carries its server")
        }

        // MARK: Helpers

        /// Writes a .zip whose entries are fixture files, or unparsable text for a nil fixture, and imports it.
        private func importZip(_ entries: [(String, String?)], root: URL) async throws -> MacAppModel {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let destination = try await MacTunnelArchive.write(
                names: entries.map(\.0), to: root.appendingPathComponent("tunnels.zip"),
            ) { index in
                var data = try entries[index].1.map { try Data(EditorFixtures.bytes($0)) } ?? Data("not a configuration\n".utf8)
                return try SecretText(bytes: SecretBytes(wiping: &data))
            }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            app.importURLs([destination])
            return app
        }

        private func source(_ path: String) throws -> String {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            return try String(contentsOf: root.appending(path: path), encoding: .utf8)
        }
    }
#endif
