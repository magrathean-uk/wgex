// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct ExportModelTests {
    @Test(arguments: [
        "single-peer-full-tunnel",
        "multi-peer-split",
        "ipv6-dual-stack",
        "crlf-bom",
        "comments-and-whitespace",
        "server-two-peers",
    ])
    func `lossless export preserves fixture bytes and public output contains no keys`(_ fixture: String) throws {
        let parsed = try EditorFixtures.parsed(fixture)
        let model = ExportModel(parsed: consume parsed)
        let leaked = try EditorFixtures.containsSecret(model.shareableText)
        #expect(!leaked)
        #expect(model.shareableText.contains("$WGEX_SECRET:"))
        model.request(.file); model.confirm()
        let exported = try model.confirmedFileText()
        let expected = try EditorFixtures.bytes(fixture)
        let matches = exported.bytes.withUnsafeBytes { $0.elementsEqual(expected) }
        #expect(matches)
        let leakedDescription = try EditorFixtures.containsSecret(model.description + String(reflecting: model))
        #expect(!leakedDescription)
        #expect(Mirror(reflecting: model).children.isEmpty)
        #expect(model.suggestedFilename.hasSuffix(".conf"))
    }

    @Test
    func `QR payload is exactly normalised wg quick text`() throws {
        let parsed = try EditorFixtures.parsed()
        let expected = try serialiseWgQuick(parsed.profile, secrets: parsed.secrets)
        let model = ExportModel(parsed: consume parsed)
        model.request(.qr); model.confirm()
        let payload = try model.confirmedQRPayload()
        let equal = payload.bytes.constantTimeEquals(expected.bytes)
        #expect(equal)
    }

    @Test
    func `grants are explicit purpose bound cancelled and single use`() throws {
        let parsed = try EditorFixtures.parsed()
        let model = ExportModel(parsed: consume parsed)
        #expect(throws: ExportError.confirmationRequired) { _ = try model.confirmedFileText() }
        model.request(.qr)
        #expect(throws: ExportError.confirmationRequired) { _ = try model.confirmedQRPayload() }
        model.confirm()
        #expect(throws: ExportError.confirmationRequired) { _ = try model.confirmedFileText() }
        _ = try model.confirmedQRPayload()
        #expect(throws: ExportError.confirmationRequired) { _ = try model.confirmedQRPayload() }
        model.request(.file); model.confirm(); model.cancel()
        #expect(throws: ExportError.confirmationRequired) { _ = try model.confirmedFileText() }
    }

    @Test
    func `edited profiles export normalised bytes rather than retained originals`() throws {
        let parsed = try EditorFixtures.parsed()
        let editor = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        editor.draft.name = "Edited"
        editor.draft.mtu = "1380"
        let profile = try editor.validatedProfile()
        #expect(profile.original == nil)
        let secrets = try editor.makeSecrets()
        let expected = try serialiseWgQuick(profile, secrets: secrets)
        let model = ExportModel(profile: profile, secrets: consume secrets)
        model.request(.file); model.confirm()
        let output = try model.confirmedFileText()
        let equal = output.bytes.constantTimeEquals(expected.bytes)
        #expect(equal)
    }
}
