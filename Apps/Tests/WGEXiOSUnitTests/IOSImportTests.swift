// SPDX-License-Identifier: MIT

import Foundation
import Testing
@testable import WGEX
import WGEXCore
import WGEXProfileStore
import WGEXUI

/// Hosted tests for every add-a-tunnel source, driven through the model entry points with injected bytes.
@MainActor @Suite(.serialized)
private struct IOSImportTests {
    private func makeModel() -> AppModel {
        AppModel(arguments: ["-WGEXFakeBackend"], simulator: true)
    }

    private func finish(_ model: AppModel) {
        try? FileManager.default.removeItem(at: model.container)
    }

    // MARK: QR code

    @Test
    func `a scanned QR payload reviews then imports and keeps no key text`() async throws {
        let model = makeModel()
        defer { finish(model) }
        let fixture = try IOSImportFixtures.fixture()
        model.prepareScannedCode(fixture.text)
        #expect(model.review?.name == "Imported profile")
        #expect(model.profiles.isEmpty)
        await model.confirmImport()
        let profile = try #require(model.profiles.first)
        #expect(model.review == nil)
        let stored = try String(decoding: JSONEncoder().encode(profile), as: UTF8.self)
        #expect(!stored.contains(fixture.privateKey))
        #expect(!(model.operationMessage ?? "").contains(fixture.privateKey))
        #expect(try await model.store.list().count == 1)
    }

    @Test(arguments: ["https://example.com/x", "hello", "", "[Peer]\nPublicKey = abc"])
    func `a non WireGuard QR payload shows a plain message`(_ payload: String) {
        let model = makeModel()
        defer { finish(model) }
        model.prepareScannedCode(payload)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.notQRConfiguration)
        #expect(model.profiles.isEmpty)
    }

    @Test(arguments: [
        (IOSScanFailure.cameraDenied, IOSImportMessage.cameraDenied),
        (.cameraUnavailable, IOSImportMessage.cameraUnavailable),
        (.unreadable, IOSImportMessage.unreadableCode),
    ])
    func `scanner failures show their own message and start no review`(_ failure: IOSScanFailure, _ message: String) {
        let model = makeModel()
        defer { finish(model) }
        model.prepareImport("[Interface]")
        model.reportScanFailure(failure)
        #expect(model.review == nil)
        #expect(model.operationMessage == message)
    }

    // MARK: Files

    @Test
    func `a conf file is named from its file name and reviewed`() async throws {
        let model = makeModel()
        defer { finish(model) }
        try model.importFile(Data(IOSImportFixtures.fixture().text.utf8), name: "Home office", isArchive: false)
        #expect(model.review?.name == "Home office")
        await model.confirmImport()
        #expect(model.profiles.map(\.name) == ["Home office"])
    }

    @Test
    func `a picked file URL is read with its extension and refused when unreadable`() throws {
        let model = makeModel()
        defer { finish(model) }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let url = folder.appendingPathComponent("office.conf")
        try Data(IOSImportFixtures.fixture().text.utf8).write(to: url)
        model.importFile(at: url)
        #expect(model.review?.name == "office")
        model.importFile(at: folder.appendingPathComponent("missing.conf"))
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.unreadableFile)
    }

    @Test
    func `an oversized or non configuration file is refused with its own message`() throws {
        let model = makeModel()
        defer { finish(model) }
        let limit = IOSImportSources.maximumConfigurationBytes
        try model.importFile(Data(IOSImportFixtures.fixture(padding: limit).text.utf8), name: "big", isArchive: false)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.tooLarge)
        model.importFile(Data("just some notes".utf8), name: "notes", isArchive: false)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.notConfiguration)
        model.importFile(Data(count: IOSImportSources.maximumBytes + 1), name: "huge", isArchive: true)
        #expect(model.operationMessage == IOSImportMessage.tooLarge)
    }

    @Test
    func `a file that parses badly still opens a review that cannot import`() {
        let model = makeModel()
        defer { finish(model) }
        model.importFile(Data("[Interface]\nPrivateKey = nope\n".utf8), name: "broken", isArchive: false)
        #expect(model.review?.canImport == false)
        #expect(model.review?.name == "broken")
    }

    // MARK: Archives

    @Test
    func `every configuration in an archive is reviewed and imported or refused with its own reason`() async throws {
        let model = makeModel()
        defer { finish(model) }
        let good = try IOSImportFixtures.fixture().text, other = try IOSImportFixtures.fixture().text
        let archive = IOSImportFixtures.zip([
            ("work.conf", Array(good.utf8)), ("notes.txt", Array("ignored".utf8)),
            ("broken.conf", Array("[Interface]\nPrivateKey = nope\n".utf8)), ("home.conf", Array(other.utf8)),
        ])
        model.importFile(archive, name: "tunnels", isArchive: true)
        #expect(model.pendingReviewCount == 3)
        #expect(model.review?.name == "work")
        await model.confirmImport()
        #expect(model.pendingReviewCount == 2)
        #expect(model.review?.name == "broken")
        #expect(model.review?.canImport == false)
        model.skipReview()
        #expect(model.review?.name == "home")
        await model.confirmImport()
        #expect(model.review == nil)
        #expect(Set(model.profiles.map(\.name)) == ["work", "home"])
        #expect(try await model.store.list().count == 2)
    }

    @Test
    func `a later entry sees the profiles imported before it`() async throws {
        let model = makeModel()
        defer { finish(model) }
        let text = try IOSImportFixtures.fixture().text
        model.importFile(
            IOSImportFixtures.zip([("a/office.conf", Array(text.utf8)), ("b/office.conf", Array(text.utf8))]),
            name: "x",
            isArchive: false,
        )
        #expect(model.pendingReviewCount == 2)
        #expect(model.review?.duplicates.isEmpty == true)
        await model.confirmImport()
        let second = try #require(model.review)
        #expect(second.duplicates.contains { $0.sameName && $0.samePublicKey })
    }

    @Test
    func `archive limits hold at the entry count and entry size`() throws {
        let model = makeModel()
        defer { finish(model) }
        let conf = try Array(IOSImportFixtures.fixture().text.utf8)
        // 1,024 entries, one of them a configuration: accepted.
        var entries: [(String, [UInt8])] = (0 ..< 1023).map { ("f\($0).txt", [65]) }
        entries.append(("ok.conf", conf))
        model.importFile(IOSImportFixtures.zip(entries), name: "full", isArchive: true)
        #expect(model.pendingReviewCount == 1)
        // 1,025 entries: refused whole.
        entries.append(("one-more.txt", [65]))
        model.importFile(IOSImportFixtures.zip(entries), name: "over", isArchive: true)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.tooLarge)
        // An entry exactly at the parser's byte cap is reviewed; one byte more refuses the archive.
        let limit = ZipArchiveReader.maximumEntryBytes
        let atLimit = try Array(IOSImportFixtures.fixture().text.utf8) + [UInt8(ascii: "\n"), UInt8(ascii: "#")]
        let padded = atLimit + Array(repeating: UInt8(ascii: "x"), count: limit - atLimit.count)
        model.importFile(IOSImportFixtures.zip([("edge.conf", padded)]), name: "edge", isArchive: true)
        #expect(model.pendingReviewCount == 1)
        model.importFile(IOSImportFixtures.zip([("edge.conf", padded + [UInt8(ascii: "x")])]), name: "edge", isArchive: true)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.tooLarge)
    }

    @Test
    func `a corrupt or truncated archive is refused whole`() throws {
        let model = makeModel()
        defer { finish(model) }
        var archive = try IOSImportFixtures.zip([("a.conf", Array(IOSImportFixtures.fixture().text.utf8))])
        archive[40] ^= 1
        model.importFile(archive, name: "bad", isArchive: true)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.badArchive)
        model.importFile(Data("PK\u{3}\u{4}garbage".utf8), name: "bad", isArchive: false)
        #expect(model.review == nil)
        #expect(model.operationMessage == IOSImportMessage.badArchive)
    }

    @Test
    func `an archive with no configurations is refused with the archive message`() {
        let model = makeModel()
        defer { finish(model) }
        model.importFile(IOSImportFixtures.zip([("readme.txt", Array("hello".utf8))]), name: "x", isArchive: true)
        #expect(model.pendingReviewCount == 0)
        #expect(model.operationMessage == IOSImportMessage.badArchive)
    }

    @Test
    func `an Open In copy in Documents Inbox is deleted after import or refusal and other files are kept`() throws {
        let model = makeModel()
        defer { finish(model) }
        let inbox = try #require(IOSImportSources.inboxDirectory)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        let good = inbox.appendingPathComponent("\(UUID().uuidString).conf")
        let bad = inbox.appendingPathComponent("\(UUID().uuidString).conf")
        try Data(IOSImportFixtures.fixture().text.utf8).write(to: good)
        try Data("not a configuration".utf8).write(to: bad)
        model.importFile(at: good)
        #expect(model.review != nil)
        #expect(!FileManager.default.fileExists(atPath: good.path))
        model.importFile(at: bad)
        #expect(model.operationMessage == IOSImportMessage.notConfiguration)
        #expect(!FileManager.default.fileExists(atPath: bad.path))
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let outside = folder.appendingPathComponent("keep.conf")
        try Data(IOSImportFixtures.fixture().text.utf8).write(to: outside)
        model.importFile(at: outside)
        #expect(model.review != nil)
        #expect(FileManager.default.fileExists(atPath: outside.path))
    }

    @Test
    func `archive payloads are wiped after each entry`() throws {
        let accounting = ZipArchiveReader.Accounting()
        IOSImportSources.accounting = accounting
        defer { IOSImportSources.accounting = nil }
        let model = makeModel()
        defer { finish(model) }
        let text = try IOSImportFixtures.fixture().text
        model.importFile(IOSImportFixtures.zip([("a.conf", Array(text.utf8)), ("b.conf", Array(text.utf8))]), name: "x", isArchive: true)
        #expect(model.pendingReviewCount == 2)
        #expect(accounting.unwiped == 0)
        #expect(accounting.retained == 0)
        #expect(accounting.live == 0)
    }

    @Test
    func `cancelling the queue drops every pending review`() throws {
        let model = makeModel()
        defer { finish(model) }
        let text = try IOSImportFixtures.fixture().text
        model.importFile(IOSImportFixtures.zip([("a.conf", Array(text.utf8)), ("b.conf", Array(text.utf8))]), name: "x", isArchive: true)
        model.cancelImport()
        #expect(model.review == nil)
        #expect(model.pendingReviewCount == 0)
        #expect(model.profiles.isEmpty)
    }

    // MARK: Create from scratch

    @Test
    func `create from scratch has a generated key pair and saves once the peer is filled`() async throws {
        let model = makeModel()
        defer { finish(model) }
        model.createFromScratch()
        let editor = try #require(model.editor)
        #expect(!editor.canSave)
        #expect(!editor.needsPrivateKey)
        editor.draft.name = "Scratch"
        editor.draft.addresses = "10.9.0.2/32"
        editor.addPeer()
        let peer = try #require(editor.draft.peers.first)
        editor.draft.peers[0].publicKey = try PrivateKey.generate().publicKey().base64
        editor.draft.peers[0].endpoint = "vpn.example.invalid:51820"
        editor.allTraffic(peerID: peer.id)
        editor.draft.protection.ipv6Policy = .blockOutside
        #expect(editor.canSave)
        let profile = try editor.validatedProfile()
        let secrets = try editor.makeSecrets()
        try model.saveEditor(profile, secrets: secrets)
        for _ in 0 ..< 300 where model.profiles.isEmpty {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(model.profiles.map(\.name) == ["Scratch"])
        #expect(model.selectedProfileID == profile.id)
        #expect(model.editor == nil)
        #expect(try await model.store.list().count == 1)
    }
}

/// Configuration and archive builders for the import tests.
private enum IOSImportFixtures {
    struct Fixture {
        let text: String
        let privateKey: String
        let publicKey: String
    }

    static func fixture(padding: Int = 0) throws -> Fixture {
        let key = try PrivateKey.generate(), peer = try PrivateKey.generate()
        var encoded = try SecretBytes(zeroedCount: 44)
        try key.encode(into: &encoded, encoding: .base64)
        let privateKey = encoded.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        let publicKey = try peer.publicKey().base64
        var text = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 192.0.2.2/32
        [Peer]
        PublicKey = \(publicKey)
        Endpoint = vpn.example.invalid:51820
        AllowedIPs = 0.0.0.0/0
        """
        if padding > 0 {
            text += "\n#" + String(repeating: "x", count: padding)
        }
        return Fixture(text: text, privateKey: privateKey, publicKey: publicKey)
    }

    /// A stored (uncompressed) ZIP32 with CRC-32, entries in the given order.
    static func zip(_ entries: [(String, [UInt8])]) -> Data {
        var result = Data(), central = Data()
        func u16(_ value: Int, to data: inout Data) {
            data.append(UInt8(truncatingIfNeeded: value)); data.append(UInt8(truncatingIfNeeded: value >> 8))
        }
        func u32(_ value: UInt32, to data: inout Data) {
            u16(Int(value & 0xFFFF), to: &data); u16(Int(value >> 16), to: &data)
        }
        for (name, payload) in entries {
            let nameBytes = Array(name.utf8), crc = CRC32.checksum(payload), local = result.count
            u32(0x0403_4B50, to: &result); u16(20, to: &result); u16(0, to: &result); u16(0, to: &result)
            u32(0, to: &result); u32(crc, to: &result); u32(UInt32(payload.count), to: &result)
            u32(UInt32(payload.count), to: &result); u16(nameBytes.count, to: &result); u16(0, to: &result)
            result.append(contentsOf: nameBytes); result.append(contentsOf: payload)
            u32(0x0201_4B50, to: &central); u16(20, to: &central); u16(20, to: &central); u16(0, to: &central)
            u16(0, to: &central); u32(0, to: &central); u32(crc, to: &central); u32(UInt32(payload.count), to: &central)
            u32(UInt32(payload.count), to: &central); u16(nameBytes.count, to: &central); u16(0, to: &central)
            u16(0, to: &central); u16(0, to: &central); u16(0, to: &central); u32(0, to: &central)
            u32(UInt32(local), to: &central); central.append(contentsOf: nameBytes)
        }
        let offset = result.count
        result.append(central)
        u32(0x0605_4B50, to: &result); u16(0, to: &result); u16(0, to: &result)
        u16(entries.count, to: &result); u16(entries.count, to: &result)
        u32(UInt32(central.count), to: &result); u32(UInt32(offset), to: &result); u16(0, to: &result)
        return result
    }
}
