// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import Testing
@testable import WGEX
import WGEXCore
import WGEXProfileStore
import WGEXUI

@MainActor
private struct IOSSettingsParityTests {
    @Test(arguments: ["paste", "QR", "file"])
    func `new imports start with on-demand off`(_ source: String) async throws {
        let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        defer { try? FileManager.default.removeItem(at: model.container) }
        let text = try TunnelListSupport.configuration()
        switch source {
        case "paste": model.prepareImport(text)
        case "QR": model.prepareScannedCode(text)
        default: model.importFile(Data(text.utf8), name: "Home", isArchive: false)
        }
        await model.confirmImport()
        let profile = try #require(model.profiles.first)
        #expect(profile.onDemand == .off)
        #expect(try await model.store.load(profile.id).onDemand == .off)
        #expect(model.operationMessage == nil)
    }

    @Test
    func `scratch starts off and importing never changes an existing saved policy`() async throws {
        let (model, _, runner) = try await TunnelListSupport.rig(["Existing"])
        defer { runner.cancel() }
        try await model.openEditor(#require(model.profiles.first))
        let editor = try #require(model.editor)
        editor.iosOnDemand = IOSOnDemandForm(wifi: true)
        try await model.commitEdit(editor.validatedProfile(), model: editor)
        let saved = try #require(model.profiles.first)
        model.createFromScratch()
        #expect(model.editor?.iosOnDemand.isEnabled == false)
        model.closeEditor()
        try model.prepareImport(TunnelListSupport.configuration())
        await model.confirmImport()
        #expect(model.profiles.count == 2)
        #expect(model.profiles.last?.onDemand == .off)
        #expect(try await model.store.load(saved.id).onDemand == saved.onDemand)
        await TunnelListSupport.finish(model, runner)
    }

    @Test
    func `a saved relay flag cannot expose the parked transport editor`() async throws {
        let (seed, _, seedRunner) = try await TunnelListSupport.rig(["Home"])
        var settings = try await seed.store.loadSettings()
        settings.app.featureFlags.relayTransports = true
        try await seed.store.saveSettings(settings)
        seedRunner.cancel()
        await seedRunner.value
        let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true, container: seed.container)
        let runner = Task { await model.run() }
        defer { runner.cancel() }
        try await TunnelListSupport.until { model.profiles.count == 1 && !model.statusHistory.isEmpty }
        #expect(!model.featureFlags.relayTransports)
        // Fake secrets are intentionally not retained across launches; scratch uses the same shared editor with fresh keys.
        model.createFromScratch()
        let editor = try #require(model.editor)
        #expect(!editor.featureFlags.relayTransports)
        await TunnelListSupport.finish(model, runner)
    }

    @Test
    func `archive exports every tunnel and round trips configuration and keys`() async throws {
        let (model, _, runner) = try await TunnelListSupport.rig(["Home", "Office"])
        defer { runner.cancel() }
        try await model.openEditor(#require(model.profiles.first))
        let editor = try #require(model.editor)
        var encoded = try SecretBytes(zeroedCount: 44)
        try PrivateKey.generate().encode(into: &encoded, encoding: .base64)
        try editor.setPresharedKey(encoded, peerID: #require(editor.draft.peers.first?.id))
        try await model.commitEdit(editor.validatedProfile(), model: editor)
        let snapshot = model.profiles
        let url = try await model.exportArchive()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let data = try Data(contentsOf: url)
        var entries = 0
        try ZipArchiveReader.scan(data) { name, bytes in
            let source = snapshot[entries]
            #expect(name == source.name)
            let parsed = try parseWgQuick(&bytes, name: name)
            #expect(parsed.profile.interface == source.interface)
            var comparable = parsed.profile
            comparable.secrets = source.secrets
            #expect(serialiseWgQuick(comparable) == serialiseWgQuick(source))
            entries += 1
        }
        #expect(entries == snapshot.count)
        // The exported bytes are also accepted by the production import path.
        let imported = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        defer { try? FileManager.default.removeItem(at: imported.container) }
        imported.importFile(data, name: "WireGuard", isArchive: true)
        for _ in snapshot {
            await imported.confirmImport()
        }
        #expect(imported.profiles.map(\.name) == snapshot.map(\.name))
        #expect(imported.profiles.allSatisfy { $0.onDemand == .off })
        for (source, copy) in zip(snapshot, imported.profiles) {
            try await expectSameKeys(source, model: model, copy: copy, imported: imported)
        }
        await TunnelListSupport.finish(model, runner)
    }

    @Test
    func `missing key refuses the whole archive and retry works after restoring it`() async throws {
        let (model, _, runner) = try await TunnelListSupport.rig(["Home", "Office"])
        defer { runner.cancel() }
        let profile = try #require(model.profiles.last)
        guard case let .daemonStore(id) = profile.secrets.privateKey else { Issue.record("Expected test key identity"); return }
        let identity = SecretID(profileID: profile.id, kind: .privateKey, id: id)
        let key = try await model.secrets.load(identity)
        try await model.secrets.delete(identity)
        await #expect(throws: SecretStoreError.notFound) { try await model.exportArchive() }
        #expect(!model.isBusy)
        try await model.secrets.store(key, for: identity)
        let url = try await model.exportArchive()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(!model.isBusy)
        await TunnelListSupport.finish(model, runner)
    }

    @Test
    func `archive refuses empty oversized and unwritable requests and can retry`() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("tunnels.zip")
        await #expect(throws: IOSTunnelArchive.Failure.empty) {
            try await IOSTunnelArchive.write(names: [], to: url) { _ in try Self.configuration() }
        }
        await #expect(throws: IOSTunnelArchive.Failure.tooManyTunnels) {
            try await IOSTunnelArchive.write(names: Array(repeating: "Home", count: IOSTunnelArchive.maximumEntries + 1), to: url) { _ in
                try Self.configuration()
            }
        }
        await #expect(throws: IOSTunnelArchive.Failure.tooLarge) {
            try await IOSTunnelArchive.write(names: ["Home"], to: url, byteLimit: 1) { _ in try Self.configuration() }
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
        await #expect(throws: IOSTunnelArchive.Failure.writeFailed) {
            try await IOSTunnelArchive.write(names: ["Home"], to: url.appendingPathComponent("bad.zip")) { _ in try Self.configuration() }
        }
        try await IOSTunnelArchive.write(names: ["Home"], to: url) { _ in try Self.configuration() }
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test
    func `archive names stay flat unique and bounded`() {
        let names = IOSTunnelArchive.entryNames(for: ["../Home", "a/b", "a\\b", "A_B", "", String(repeating: "é", count: 300)])
        #expect(Set(names.map { $0.lowercased() }).count == names.count)
        #expect(names.allSatisfy { !$0.contains("/") && !$0.contains("\\") && $0.hasSuffix(".conf") && $0.utf8.count <= 255 })
    }

    @Test
    func `iOS screens have no parked controls and version matches the pinned engine`() throws {
        let screens = Self.root.appendingPathComponent("Packages/WGEXUI/Sources/WGEXUI/Screens/iOS")
        let files = try FileManager.default.contentsOfDirectory(at: screens, includingPropertiesForKeys: nil)
        for file in files where file.pathExtension == "swift" {
            try Self.expectNoParkedControls(String(contentsOf: file, encoding: .utf8))
        }
        let model = AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
        defer { try? FileManager.default.removeItem(at: model.container) }
        let engine = try String(contentsOf: Self.root.appendingPathComponent("Engine/go/engine/engine.go"), encoding: .utf8)
        #expect(engine.contains("WireGuardCommit = \"\(model.engineVersion)"))
        let plist = try Data(contentsOf: Self.root.appendingPathComponent("Apps/WGEXiOS/Info.plist"))
        let info = try #require(PropertyListSerialization.propertyList(from: plist, format: nil) as? [String: Any])
        #expect(!(info["NSLocalNetworkUsageDescription"] as? String ?? "").contains("pair"))
        #expect(info["NSBonjourServices"] == nil)
        let project = try String(contentsOf: Self.root.appendingPathComponent("project.yml"), encoding: .utf8)
        let target = try #require(project.components(separatedBy: "  WGEXiOS:\n").last?.components(separatedBy: "  WGEXTunnel-iOS:\n")
            .first)
        #expect(!target.contains("package: WGEXPairing"))
    }

    @Test
    func `negative control catches a parked control reintroduced into a screen`() {
        withKnownIssue("Negative control: parked control reintroduced") {
            Self.expectNoParkedControls("Toggle(\"Automatic failover\", isOn: binding)")
        }
    }

    private func expectSameKeys(_ source: TunnelProfile, model: AppModel, copy: TunnelProfile, imported: AppModel) async throws {
        await model.openEditor(source)
        let original = try #require(model.editor).makeSecrets()
        await imported.openEditor(copy)
        let restored = try #require(imported.editor).makeSecrets()
        var expected = try SecretBytes(zeroedCount: 32), actual = try SecretBytes(zeroedCount: 32)
        try original.withKey(source.secrets.privateKey) { key in expected.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
        try restored.withKey(copy.secrets.privateKey) { key in actual.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
        let keysMatch = expected.constantTimeEquals(actual)
        #expect(keysMatch)
        for (peer, reference) in source.secrets.presharedKeys {
            let copyReference = try #require(copy.secrets.presharedKeys[peer])
            try original.withKey(reference) { key in expected.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            try restored.withKey(copyReference) { key in actual.withUnsafeMutableBytes { $0.copyMemory(from: key) } }
            let presharedMatches = expected.constantTimeEquals(actual)
            #expect(presharedMatches)
        }
    }

    private static var root: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private static func expectNoParkedControls(_ source: String, sourceLocation: SourceLocation = #_sourceLocation) {
        for token in [
            "Automatic failover",
            "TransportSettingsSection",
            "Choose transport",
            "Notifications",
            "Notification delivery",
            "fake backend",
        ] {
            let absent = !source.contains(token)
            #expect(absent, "FAIL: parked iOS control is reachable", sourceLocation: sourceLocation)
        }
    }

    private static func configuration() throws -> SecretText {
        var bytes = try Array(TunnelListSupport.configuration().utf8)
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        let parsed = try parseWgQuick(&bytes, name: "Home")
        return try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
    }
}
