// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDiagnostics

private struct RedactorOffsetTests {
    @Test
    func `UTF8 to UTF16 offsets agree at every scalar boundary`() {
        let text = "🙂界e\u{301}\r\nleft\n右🛰️tail"
        let offsets = Redactor.utf16Offsets(text)
        var bytes = 0
        for scalar in text.unicodeScalars {
            #expect(offsets[bytes] == String(decoding: text.utf8.prefix(bytes), as: UTF8.self).utf16.count)
            for interior in 1 ..< scalar.utf8.count {
                #expect(offsets[bytes + interior] == -1)
            }
            bytes += scalar.utf8.count
        }
        #expect(offsets[bytes] == (text as NSString).length)
    }

    @Test
    func `pattern ranges preserve Unicode and physical line break offsets`() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let fixture = try String(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/server.pub"), encoding: .utf8)
        let key = try #require(fixture.split(separator: "\n").first { !$0.hasPrefix("#") && !$0.isEmpty }).description
        let split = String(key.prefix(20)) + "\r\n" + key.dropFirst(20)
        let text = "🙂界 \(key) Ω\n🛰️ \(split) 尾"
        #expect(Redactor().redact(text) == "🙂界 <secret:1> Ω\n🛰️ <secret:1> 尾")
    }
}
