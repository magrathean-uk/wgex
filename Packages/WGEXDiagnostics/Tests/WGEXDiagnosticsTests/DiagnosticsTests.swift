// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Testing
import WGEXCore
@testable import WGEXDiagnostics

private struct DiagnosticsTests {
    @Test
    func `RT-08 all 340 seeded leaks are absent from ring dumps and stored zip entries`() throws {
        let corpus = RedactionCorpus.leaks
        #expect(corpus.count == 340)
        let redactor = Redactor(exactMatches: corpus.filter(\.exact).map(\.value))
        let ring = LogRing()
        for leak in corpus {
            ring.append(leak.message, category: .transport, date: Date(timeIntervalSince1970: 0))
        }
        let lines = ring.redactedLines(using: redactor)
        #expect(lines.count == corpus.count)
        let dump = lines.map(\.message).joined(separator: "\n")
        let bundle = try DiagnosticsBundleBuilder(redactor: redactor).build(rings: [ring], createdAt: Date(timeIntervalSince1970: 0))
        let zipText = String(decoding: bundle.archive, as: UTF8.self)
        // Only booleans enter test failure output; fixture values are never printed.
        for leak in corpus {
            let ringLeaked = dump.contains(leak.value)
            let bundleLeaked = zipText.contains(leak.value)
            let characters = Array(leak.value)
            if characters.count >= 16 {
                for offset in 0 ... characters.count - 16 {
                    let fragment = String(characters[offset ..< offset + 16])
                    let partialRingLeak = dump.contains(fragment)
                    let partialBundleLeak = zipText.contains(fragment)
                    #expect(!partialRingLeak); #expect(!partialBundleLeak)
                }
            }
            #expect(!ringLeaked); #expect(!bundleLeaked)
        }
        #expect(lines.allSatisfy { $0.message.contains("<secret:") })
        #expect(bundle.filename == "wgex-diagnostics-1970-01-01.zip")
        let entries = try ZIPInspection.entries(bundle.archive)
        #expect(Set(entries.keys) == ["logs/process-0.json", "manifest.json"])
        let manifest = try JSONDecoder().decode(TestManifest.self, from: #require(entries["manifest.json"]))
        for entry in manifest.entries {
            let data = try #require(entries[entry.name])
            #expect(entry.sha256 == SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
        }
        #if os(macOS)
            try ZIPInspection.checkWithUnzip(bundle.archive)
        #endif
    }

    @Test
    func `short exact registration cannot split an unregistered unpadded key`() {
        let key = String(Data((0 ..< 32).map { UInt8($0 * 7) }).base64EncodedString().dropLast())
        let redactor = Redactor(exactMatches: [String(key.dropFirst(21).prefix(1))])
        let output = redactor.redact(key)
        for offset in 0 ... key.count - 9 {
            let leaked = output.contains(String(key.dropFirst(offset).prefix(9)))
            #expect(!leaked)
        }
    }

    @Test
    func `overlapping and adjacent exact and pattern spans are replaced once`() {
        let key = String(Data((0 ..< 32).map(UInt8.init)).base64EncodedString().dropLast())
        let overlapping = Redactor(exactMatches: ["prefix:" + String(key.prefix(10))])
        #expect(overlapping.redact("prefix:" + key) == "<secret:1>")
        let adjacent = Redactor(exactMatches: ["left", "right"])
        #expect(adjacent.redact("leftright") == "<secret:1>")
        let mixed = Redactor(exactMatches: ["!"])
        #expect(mixed.redact("!" + key) == "<secret:1>")
    }

    @Test
    func `unicode identifiers retain twelve character windows and correct UTF16 span boundaries`() {
        let name = String(repeating: "🌍界", count: 9)
        let redactor = Redactor(exactMatches: [name])
        let fragment = String(name.dropFirst(3).prefix(12))
        #expect(redactor.redact("é " + name + " end") == "é <secret:1> end")
        #expect(redactor.redact(fragment) == "<secret:1>")
    }

    @Test
    func `borrowed secret registration retains only fingerprints and replacement Strings`() throws {
        var bytes = Data("synthetic private token with punctuation!".utf8)
        let secret = try SecretBytes(wiping: &bytes)
        let redactor = Redactor()
        redactor.register(secret)
        #expect(redactor.retainedStrings.allSatisfy { $0.hasPrefix("<secret:") && $0.hasSuffix(">") })
        let output = secret.withUnsafeBytes { redactor.redact(String(decoding: $0, as: UTF8.self)) }
        #expect(output == "<secret:1>")
        let rawRedactor = Redactor()
        secret.withUnsafeBytes { rawRedactor.register($0) }
        #expect(rawRedactor.retainedStrings == redactor.retainedStrings)
    }

    @Test
    func `exact matches precede patterns and correlate full partial and split values`() {
        let secret = Data((0 ..< 32).map(UInt8.init)).base64EncodedString()
        let redactor = Redactor(exactMatches: [secret])
        let full = redactor.redact(secret)
        #expect(full == "<secret:1>")
        for offset in 0 ... secret.count - 12 {
            let fragment = String(secret.dropFirst(offset).prefix(12))
            #expect(redactor.redact(fragment) == full)
        }
        let split = String(secret.prefix(21)) + "\r\n" + secret.dropFirst(21)
        #expect(redactor.redact(split) == full)
        #expect(redactor.redact(secret + " " + secret) == full + " " + full)
        #expect(redactor.redact(full) == full)
    }

    @Test(arguments: [
        "192.0.2.1", "192.0.2.0/24", "10/8", "172.16/12", "192.168.1/24", "::", "::/0", "::1", "2001:db8::1",
        "2001:db8::/32", "fe80::1%en0", "::ffff:192.0.2.1", "[2001:db8::1]:51820",
    ])
    func `endpoints are private by default and preserved only by explicit option`(value: String) {
        let privateValue = Redactor().redact(value)
        #expect(!privateValue.contains(value))
        #expect(Redactor(includeEndpoints: true).redact(value) == value)
    }

    @Test(arguments: [
        "PrivateKey = malformed-secret", "PresharedKey = malformed-secret", "path=/private/ws", "\"path\":\"/private/ws\"",
        "sni=private.example.test", "\"host\": \"private.example.test\"", "host=192.0.2.1",
    ])
    func `named sensitive fields are removed without exact registrations`(message: String) {
        #expect(Redactor().redact(message).contains("<secret:"))
    }

    @Test
    func `hex and all 42 to 44 character alphabets are caught`() {
        // Every rule compiles (a failed rule fails closed to "<redacted>") and ordinary text survives.
        let ordinary = "handshake at 17:55:38 after 3 attempts, mtu 1420"
        #expect(Redactor().redact(ordinary) == ordinary)
        let hex = String(repeating: "a7", count: 32)
        #expect(Redactor().redact(hex) == "<secret:1>")
        for length in 42 ... 44 {
            for alphabet in ["a+/b", "a-_b"] {
                let token = String(String(repeating: alphabet, count: 11).prefix(length))
                #expect(Redactor().redact(token) == "<secret:1>")
            }
        }
    }

    @Test
    func `public wrapper is an allowlist and descriptions omit private values`() {
        let privateValue = "sensitive-profile.example.test"
        let message: LogMessage = "profile \(privateValue) count \(PublicLogValue.count(4))"
        #expect(message.publicText == "profile <private> count 4")
        #expect(message.privateText.contains(privateValue))
        let descriptions = [
            String(describing: message),
            String(reflecting: message),
            String(describing: Redactor(exactMatches: [privateValue])),
            String(reflecting: DiagnosticsSection(kind: .systemInfo, text: privateValue)),
        ]
        #expect(descriptions.allSatisfy { !$0.contains(privateValue) })
        // No OS log emission in tests; inspect the exact payload passed to os.Logger.
    }

    @Test
    func `bundle cap includes zip metadata and source errors never reflect caller text`() throws {
        #expect(throws: DiagnosticsError.sizeLimit) {
            _ = try DiagnosticsBundleBuilder(redactor: Redactor()).build(rings: [], sources: [LargeSection()])
        }
        #expect(throws: DiagnosticsError.sectionUnavailable) {
            _ = try DiagnosticsBundleBuilder(redactor: Redactor()).build(rings: [], sources: [FailingSection()])
        }
        #expect(throws: DiagnosticsError.sizeLimit) {
            _ = try StoredZIP.archive([StoredZIP.Entry(name: "a", data: Data(count: 40))], maximumBytes: 100)
        }
        let builder = DiagnosticsBundleBuilder(redactor: Redactor(exactMatches: ["private.example.test"]))
        let first = try builder.build(rings: [], sources: [SmallSection()], createdAt: Date(timeIntervalSince1970: 0))
        let second = try builder.build(rings: [], sources: [SmallSection()], createdAt: Date(timeIntervalSince1970: 100))
        #expect(first.archive == second.archive)
        #expect(!String(decoding: first.archive, as: UTF8.self).contains("private.example.test"))
        #expect(first.archive.count < DiagnosticsBundleBuilder.maximumBytes)
    }
}

private struct LargeSection: DiagnosticsSectionSource {
    func diagnosticsSections() -> [DiagnosticsSection] {
        [DiagnosticsSection(kind: .systemInfo, text: String(repeating: ".", count: DiagnosticsBundleBuilder.maximumBytes))]
    }
}

private struct SmallSection: DiagnosticsSectionSource {
    func diagnosticsSections() -> [DiagnosticsSection] {
        [DiagnosticsSection(kind: .dns, text: "host=private.example.test")]
    }
}

private struct FailingSection: DiagnosticsSectionSource {
    private struct Failure: Error { let text = "sensitive-source-detail" }
    func diagnosticsSections() throws -> [DiagnosticsSection] {
        throw Failure()
    }
}

private struct TestManifestEntry: Decodable {
    let name: String
    let sha256: String
}

private struct TestManifest: Decodable {
    let entries: [TestManifestEntry]
}
