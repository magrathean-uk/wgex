// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXTesting

/// Key-shaped strings are built at run time so no literal trips the
/// repository's secret lint.
private struct SecretScannerTests {
    @Test
    func `key-shaped base64 and hex are found`() {
        let base64Key = Data(repeating: 7, count: 32).base64EncodedString()
        let hexKey = String(repeating: "ab", count: 32)
        let scanner = SecretScanner()
        let found = scanner.findings(in: "key=\(base64Key) psk \(hexKey)")
        #expect(found.map(\.kind) == [.keyShapedBase64, .hex64])
        #expect(found.first?.offset == 4)
    }

    @Test
    func `ordinary text is clean`() {
        let scanner = SecretScanner()
        #expect(scanner.isClean("handshake completed with peer 3 after 120 ms"))
        #expect(scanner.isClean(String(repeating: "ab", count: 33)))
    }

    @Test
    func `registered secrets are found in every encoding`() throws {
        var secret = try SecretBytes(zeroedCount: 20)
        secret.withUnsafeMutableBytes { raw in
            for index in raw.indices {
                raw[index] = UInt8(index * 3)
            }
        }
        var scanner = SecretScanner()
        scanner.register(secret)
        let raw = secret.withUnsafeBytes { Data($0) }
        #expect(scanner.findings(in: Data("x".utf8) + raw).map(\.kind) == [.registeredSecret])
        #expect(!scanner.isClean("log: \(raw.base64EncodedString())"))
        #expect(!scanner.isClean(raw.map { String(format: "%02x", $0) }.joined()))
    }
}
