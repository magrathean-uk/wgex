// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M07-T04: Add, Review, Edit, Export, Delete and the empty window. Holds the pins moved from `MacSourceContractTests` and
    /// `MacWindowShellTests` in M07-T03's seam commit.
    @MainActor
    @Suite("M07-T04 tunnel sheets", .timeLimit(.minutes(1)))
    private struct MacTunnelSheetsTests {
        @Test func `import review keeps its IPv6 picker and duplicate identifiers`() throws {
            let ids = Set(WGEXAccessibility.catalogue.map(\.id))
            #expect(ids.contains("wgex.importReview.ipv6"))
            #expect(ids.contains("wgex.importReview.duplicate"))
            for path in ["Import/ImportReviewScreen.swift", "Screens/Mac/MacImportSheet.swift"] {
                let source = try source("Packages/WGEXUI/Sources/WGEXUI/\(path)")
                #expect(source.contains("showsIPv6PolicyChoice"))
                #expect(source.contains("ImportIPv6PolicyPicker"))
            }
        }

        @Test func `sidebar Add Tunnel routes the window and opens the import sheet`() throws {
            let app = try source("Apps/WGEXMac/WGEXMacApp.swift")
            #expect(app.contains("addProfile: { model.routeWindow(.importTunnel); model.openImport() }"))
        }

        // MARK: Add a Tunnel (SPEC 6.1)

        @Test func `Add a Tunnel has three rows in SPEC words and no QR import`() throws {
            #expect(MacStrings.addATunnelTitle == "Add a Tunnel")
            #expect(MacStrings.addATunnelMessage
                == "Use a WireGuard configuration made for this Mac. You can also drop a file anywhere on this window.")
            #expect(MacStrings.importFromFile == "Import from File…")
            #expect(MacStrings.pasteFromClipboard == "Paste from Clipboard")
            #expect(MacStrings.createEmptyTunnel == "Create Empty Tunnel")
            #expect(MacStrings.clipboardHoldsNoConfiguration == "The clipboard does not hold a WireGuard configuration.")
            let add = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacAddTunnelView.swift")
            for element in ["\"chooseFile\"", "\"paste\"", "\"createEmpty\""] {
                #expect(add.contains(element))
            }
            let ids = Set(WGEXAccessibility.catalogue.map(\.id))
            #expect(!ids.contains("wgex.importReview.qrFromImage"))
            #expect(ids.contains("wgex.importReview.createEmpty"))
            for path in [
                "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacAddTunnelView.swift",
                "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacImportSheet.swift",
                "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacOnboardingView.swift",
                "Apps/WGEXMac/WGEXMacApp.swift", "Apps/WGEXMac/MacAppModel+Import.swift", "Apps/WGEXMac/MacImportSources.swift",
            ] {
                let text = try source(path)
                #expect(!text.contains("qrImage") && !text.contains("qr:") && !text.contains("func qr("), "QR import in \(path)")
            }
            #expect(!MacStrings.importSourceAction.contains("QR"))
        }

        @Test func `the menu goes straight to the file picker and paste says so in one line`() throws {
            let app = try source("Apps/WGEXMac/WGEXMacApp.swift")
            let command = try #require(app.components(separatedBy: "case .importTunnel:").last)
                .components(separatedBy: "case .exportAll:")[0]
            #expect(command.contains("MacStrings.importTunnelsFromFile"))
            #expect(command.contains("model.chooseImportFile()"))
            #expect(command.contains("show(.importTunnel)"))
            let imports = try source("Apps/WGEXMac/MacAppModel+Import.swift")
            #expect(imports.contains("importErrorMessage = MacStrings.clipboardHoldsNoConfiguration"))
        }

        // MARK: Review Tunnel (SPEC 6.2)

        @Test func `review rows read All traffic for a full tunnel and list split routes`() throws {
            var profile = try EditorFixtures.parsed("ipv6-dual-stack").profile
            profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/0"), IPAddressRange("::/0")]
            #expect(MacTunnelProblems.routes(profile) == MacStrings.allTraffic)
            profile.peers[0].allowedIPs = try [IPAddressRange("0.0.0.0/0")]
            #expect(MacTunnelProblems.routes(profile) == "All traffic")
            profile.peers[0].allowedIPs = try [IPAddressRange("10.0.0.0/8"), IPAddressRange("0.0.0.0/0")]
            #expect(MacTunnelProblems.routes(profile) == "10.0.0.0/8, 0.0.0.0/0")
            #expect(MacStrings.addAndActivate == "Add and Activate")
            #expect(!MacStrings.addAndActivate.contains("Connect"))
        }

        @Test func `problems read in plain words and an error disables both Add buttons`() throws {
            let hook = ConfigDiagnostic(severity: .warning, code: .ignoredHook, line: 3)
            #expect(MacTunnelProblems.text(hook) == "Commands such as PostUp are not supported and were removed.")
            let custom = ConfigDiagnostic(severity: .error, code: .invalidKey, message: "Kept as written.")
            #expect(MacTunnelProblems.text(custom) == "Kept as written.")
            #expect(MacTunnelProblems.text(ConfigDiagnostic(severity: .error, code: .noPeers)) == MacStrings.needsAServer)
            let failed = ImportReviewModel(parseError: ConfigParseError.diagnostics([ConfigDiagnostic(
                severity: .error,
                code: .invalidKey,
            )]))
            #expect(!failed.canImport)
            let sheet = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacImportSheet.swift")
            // Both Add buttons of the single review, plus the tick-list checkbox of a row with an error (M07-T09).
            #expect(sheet.components(separatedBy: ".disabled(!review.canImport)").count == 4)
        }

        @Test func `Add All saves the clean reviews and leaves out the ones with errors`() async throws {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            let first = try EditorFixtures.parsed("ipv6-dual-stack")
            let second = try EditorFixtures.parsed("multi-peer-split")
            app.importReviews = [
                ImportReviewModel(parsed: consume first),
                ImportReviewModel(
                    parseError: ConfigParseError.diagnostics([ConfigDiagnostic(severity: .error, code: .invalidKey)]),
                    name: "Broken",
                ),
                ImportReviewModel(parsed: consume second),
            ]
            app.importing = true
            await app.confirmAllImports()?.value
            #expect(app.shell.profiles.map(\.name) == ["Home", "Home 2"])
            #expect(app.importReviews.isEmpty)
            #expect(!app.importing)
            #expect(try await app.profileStore.list().count == 2)
            #expect(MacStrings.leftOutWithErrors("Broken") == "Not added because of errors: Broken.")
        }

        // MARK: Delete (SPEC 6.4)

        private func activeShell(_ backend: FakeTunnelBackend, deleted: DeleteLog) -> (MacShellModel, TunnelProfile) {
            let profile = TunnelProfile(name: "Home")
            let shell = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: FakeServiceController(initial: .enabled), simulated: true,
                operations: MacShellOperations(deleteProfile: { deleted.ids.append($0.id) }),
            ), profiles: [profile, TunnelProfile(name: "Cabin")])
            shell.selectedProfileID = profile.id
            shell.receive(TunnelStatus(
                phase: .active(Generation(rawValue: 1)), protection: .protected, transport: nil, health: .idle, recentEvents: [],
            ), at: Date())
            return (shell, profile)
        }

        @MainActor
        private final class DeleteLog {
            var ids: [UUID] = []
        }

        private let quickWait = MacIdleWait(attempts: 3) {}

        @Test func `deleting the active tunnel deactivates it first and says so`() async {
            let backend = FakeTunnelBackend()
            let deleted = DeleteLog()
            let (shell, profile) = activeShell(backend, deleted: deleted)
            #expect(shell.deletionDeactivatesFirst(profile))
            #expect(MacDeleteTunnelAlert.message(profile, deactivatesFirst: true)
                == "This cannot be undone. Home is active. It will be deactivated first.")
            #expect(MacStrings.deleteTunnelTitle("Home") == "Delete Home?")
            await shell.deleteProfile(profile, idleWait: quickWait)
            #expect(backend.calls.contains(.stop(profile.id)))
            #expect(deleted.ids == [profile.id])
            #expect(shell.profiles.map(\.name) == ["Cabin"])
        }

        @Test func `a failed deactivation deletes nothing and says why`() async {
            let backend = FakeTunnelBackend()
            backend.faults.arm("stop", error: TunnelError.timedOut)
            let deleted = DeleteLog()
            let (shell, profile) = activeShell(backend, deleted: deleted)
            await shell.deleteProfile(profile, idleWait: quickWait)
            #expect(deleted.ids.isEmpty)
            #expect(shell.profiles.count == 2)
            #expect(shell.operationMessage?.hasPrefix(MacStrings.tunnelNotDeletedNotDeactivated("Home", reason: nil)) == true)
            #expect(shell.operationMessage != MacStrings.tunnelNotDeletedNotDeactivated("Home", reason: nil), "The reason follows")
        }

        @Test func `a tunnel that never reports idle is not deleted`() async {
            let backend = FakeTunnelBackend()
            backend.scriptStop([.init(phase: .stopping(Generation(rawValue: 1), reason: .userRequested), protection: .blocked)])
            let deleted = DeleteLog()
            let (shell, profile) = activeShell(backend, deleted: deleted)
            await shell.deleteProfile(profile, idleWait: quickWait)
            #expect(deleted.ids.isEmpty)
            #expect(shell.operationMessage == MacStrings.tunnelNotDeletedNotDeactivated("Home", reason: nil))
        }

        @Test func `deleting another tunnel while one is up stays refused in SPEC words`() async throws {
            let backend = FakeTunnelBackend()
            let deleted = DeleteLog()
            let (shell, _) = activeShell(backend, deleted: deleted)
            let other = try #require(shell.profiles.last)
            #expect(!shell.deletionDeactivatesFirst(other))
            await shell.deleteProfile(other, idleWait: quickWait)
            #expect(deleted.ids.isEmpty)
            #expect(!backend.calls.contains(.stop(other.id)))
            let message = try #require(shell.operationMessage)
            #expect(message == MacErrorCopy(.deletionBlocked).message)
            #expect(!message.contains("Disconnect"))
            #expect(message.contains("Deactivate"))
        }

        // MARK: Empty window (SPEC 6.5)

        @Test func `the empty window is centred with SPEC words and Import from File as default`() throws {
            #expect(MacStrings.noTunnelsTitle == "No Tunnels")
            #expect(MacStrings.addAConfigurationMadeForThisMac == "Add a WireGuard configuration made for this Mac.")
            #expect(MacStrings.orDropAConfFileHere == "or drop a .conf file here")
            let empty = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacEmptyTunnelsView.swift")
            let importButton = try #require(empty.components(separatedBy: "Button(MacStrings.importFromFile)").last)
                .components(separatedBy: "Button(MacStrings.pasteFromClipboard")[0]
            #expect(importButton.contains(".keyboardShortcut(.defaultAction)"))
            #expect(!empty.contains("MacProtectionPanel"))
        }

        @Test func `new copy keeps SPEC 3 words`() {
            for text in MacStrings.tunnelSheetsCatalogue {
                #expect(!text.localizedCaseInsensitiveContains("profile"), "\(text)")
                #expect(!text.contains("Allow LAN"), "\(text)")
                #expect(!text.contains("Connect"), "\(text)")
            }
        }

        private func source(_ path: String) throws -> String {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            return try String(contentsOf: root.appending(path: path), encoding: .utf8)
        }
    }
#endif
