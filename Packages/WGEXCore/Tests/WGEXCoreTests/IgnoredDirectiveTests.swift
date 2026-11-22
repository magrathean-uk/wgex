// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct IgnoredDirectiveTests {
    @Test(arguments: ["PreUp", "PostUp", "PreDown", "PostDown", "Table", "FwMark", "SaveConfig"])
    func `ignored directive values never survive original text or export`(key: String) throws {
        // Public, non-key stand-ins prove arbitrary command credentials and inline comments are removed.
        let command = "fixture-command --credential fixture-only-opaque-value # fixture-comment-credential"
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal(interface: "\(key) = \(command)").utf8))
        #expect(parsed.original.text.contains("\(key) =<removed>"))
        #expect(!parsed.original.text.contains("fixture-only-opaque-value"))
        #expect(!parsed.original.text.contains("fixture-comment-credential"))
        #expect(parsed.original.wasRedacted)
        #expect(parsed.profile.original == parsed.original)
        let encoded = try JSONEncoder().encode(parsed.profile)
        #expect(encoded.range(of: Data("fixture-only-opaque-value".utf8)) == nil)
        let exported = try exportOriginalWgQuick(parsed.original, secrets: parsed.secrets)
        let safe = exported.bytes.withUnsafeBytes { raw in
            !raw.indices.contains { raw[$0...].starts(with: "fixture-only-opaque-value".utf8) }
                && !raw.indices.contains { raw[$0...].starts(with: "fixture-comment-credential".utf8) }
        }
        #expect(safe)
        var second: ParsedConfiguration?
        try exported.bytes.withUnsafeBytes { second = try parseWgQuick(Array($0)) }
        guard let reparsed = consume second else { Issue.record("Expected a reparsed configuration"); return }
        #expect(reparsed.profile.interface == parsed.profile.interface)
        #expect(reparsed.profile.peers == parsed.profile.peers)
    }

    @Test(arguments: ["PreUp", "PostUp", "PreDown", "PostDown"])
    func `ignored hooks have a distinct warning`(key: String) throws {
        let parsed = try parseWgQuick(Array(CodecFixtures.minimal(interface: "\(key)=fixture").utf8))
        #expect(parsed.diagnostics.contains { $0.code.rawValue == "ignoredHook" && $0.severity == .warning })
        #expect(!parsed.diagnostics.contains { $0.code == .unsupportedSetting })
    }
}
