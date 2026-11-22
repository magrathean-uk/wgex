// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDiagnostics

private struct HardeningPatternTests {
    @Test(arguments: ["search domain[0] : private.search.example.test", "domain : private.search.example.test"])
    func `system DNS section search domains are private without profile registration`(line: String) {
        let leaked = Redactor().redact(line).contains("private.search.example.test")
        #expect(!leaked)
    }

    @Test(arguments: ["x=", "x==", "[", "\"x\":\""])
    func `assignment punctuation does not hide key shapes`(prefix: String) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/client1.key"))
        let key = try #require(String(data: data, encoding: .utf8)?.split(separator: "\n").first { !$0.hasPrefix("#") })
        let leaked = Redactor().redact(prefix + key + "\"").contains(key)
        #expect(!leaked)
    }

    @Test(arguments: [".", ". Next sentence", ",", ".\n", "/32."])
    func `IPv4 before sentence punctuation is private`(suffix: String) {
        let leaked = Redactor().redact("resolver 192.0.2.53" + suffix).contains("192.0.2.53")
        #expect(!leaked)
    }
}
