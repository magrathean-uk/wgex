// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Testing
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXDiagnostics
import WGEXTesting

private struct DaemonAdapterLeakTests {
    @Test
    func `export retries failed startup registration before collecting sections`() async throws {
        let adapter = DaemonDiagnosticsAdapter()
        adapter.disableExports()
        adapter.setPreparation {}
        let bundle = try await adapter.bundle(.init(includeLogs: false, since: nil, profileIDs: []), visibleProfileIDs: [])
        #expect(!bundle.archive.isEmpty)
    }

    @Test
    func `swallowed fingerprint observer failures still disable diagnostic export`() async throws {
        let adapter = DaemonDiagnosticsAdapter()
        adapter.setPreparation {
            let malformed = try SecretBytes(zeroedCount: 1)
            try? adapter.registerSecretWire(malformed)
        }
        await #expect(throws: DiagnosticsError.sectionUnavailable) {
            try await adapter.bundle(.init(includeLogs: false, since: nil, profileIDs: []), visibleProfileIDs: [])
        }
    }

    @Test(arguments: [false, true])
    func `daemon adapter registers installed and restarted fixture profiles without payload leaks`(restart: Bool) async throws {
        let bytes = try Self.fixtureKey("client1.key")
        let psk = try Self.fixtureKey("psk1.key")
        let key = try PrivateKey(bytes: SecretBytes(parsing: bytes))
        let peer = try PrivateKey(bytes: Self.fixtureKey("client2.key")).publicKey()
        var writer = try SecretsWireWriter(privateKey: bytes)
        try writer.appendPresharedKey(psk, for: peer)
        let wire = try writer.finish()
        let profile = try Self.profile(publicKey: key.publicKey(), peer: peer)
        let leak = try Self.message(bytes, psk: psk)
        let root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-diagnostic-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try StateDirectory(root: root)
        let adapter = try await Self.adapter(profile: profile, wire: wire, directory: directory, restart: restart, message: leak.text)
        let bundle = try await adapter.bundle(
            .init(includeLogs: true, since: nil, profileIDs: [profile.id]),
            visibleProfileIDs: [profile.id],
        )
        let entries = try ZIPInspection.entries(bundle.archive)
        var scanner = SecretScanner(); scanner.register(bytes); scanner.register(psk)
        try Self.verify(
            entries,
            archive: bundle.archive,
            scanner: scanner,
            privateValues: [profile.name, "private-resolver.example.test", "10.77.0.1"] + leak.fragments,
        )
        #expect(entries.keys.contains { $0.contains("-pf-") })
        #expect(entries.keys.contains { $0.contains("-routes-") })
        #expect(entries.keys.contains { $0.contains("-dns-") })
    }

    private static func profile(publicKey: PublicKey, peer: PublicKey) throws -> TunnelProfile {
        var profile = TunnelProfile(name: "Private diagnostic fixture")
        profile.interface = try InterfaceConfiguration(
            addresses: [IPAddressRange("10.77.0.2/32")],
            dns: [DNSServer("10.77.0.1")],
            publicKey: publicKey,
        )
        profile.peers = try [PeerConfiguration(
            publicKey: peer,
            hasPresharedKey: true,
            allowedIPs: [IPAddressRange("0.0.0.0/0")],
            endpoint: Endpoint("private-resolver.example.test:51820"),
        )]
        profile.protection.ipv6Policy = .blockOutside
        profile.secrets = SecretReferences(privateKey: .daemonStore(id: UUID()), presharedKeys: [peer: .daemonStore(id: UUID())])
        return profile
    }

    private static func message(_ bytes: borrowing SecretBytes, psk: borrowing SecretBytes) throws -> (text: String, fragments: [String]) {
        var encoded = try SecretBytes(zeroedCount: 44)
        try bytes.withUnsafeBytes { raw in try encoded.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) } }
        let privateFragment = encoded.withUnsafeBytes { String(decoding: $0.prefix(12), as: UTF8.self) }
        var encodedPSK = try SecretBytes(zeroedCount: 44)
        try psk.withUnsafeBytes { raw in try encodedPSK.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) } }
        let pskFragment = encodedPSK.withUnsafeBytes { String(decoding: $0.prefix(12), as: UTF8.self) }
        let message = encoded.withUnsafeBytes { "x=" + String(decoding: $0, as: UTF8.self) }
            + " Private diagnostic fixture private-resolver.example.test 10.77.0.1. " + privateFragment + " " + pskFragment
        return (message, [privateFragment, pskFragment])
    }

    private static func adapter(
        profile: TunnelProfile,
        wire: consuming SecretBytes,
        directory: StateDirectory,
        restart: Bool,
        message: String,
    ) async throws -> DaemonDiagnosticsAdapter {
        func adapter() -> DaemonDiagnosticsAdapter {
            DaemonDiagnosticsAdapter(sections: {
                [.init(kind: .pf, text: message), .init(kind: .routes, text: message), .init(kind: .dns, text: message)]
            })
        }
        let initial = adapter()
        let store = try DaemonSecretStore(
            directory: directory,
            keyProvider: InMemoryDaemonKeyProvider(key: Self.fixtureKey("psk1.key")),
            observeBundle: { try initial.registerSecretWire($0) },
        )
        let repository = try DirectoryProfileRepository(directory: directory)
        let registry = ProfileRegistry(repository: repository, secrets: store, bundles: store, profileRegistered: { initial.register($0) })
        _ = try await registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        try await store.saveBundle(wire, profileID: profile.id)
        let adapter = restart ? adapter() : initial
        if restart {
            let restoredStore = try DaemonSecretStore(
                directory: directory,
                keyProvider: InMemoryDaemonKeyProvider(key: Self.fixtureKey("psk1.key")),
                observeBundle: { try adapter.registerSecretWire($0) },
            )
            let restored = ProfileRegistry(
                repository: repository,
                secrets: restoredStore,
                bundles: restoredStore,
                profileRegistered: { adapter.register($0) },
            )
            try await restored.registerInstalledProfiles()
        }
        return adapter
    }

    private static func verify(_ entries: [String: Data], archive: Data, scanner: SecretScanner, privateValues: [String]) throws {
        for (name, data) in entries where name != "manifest.json" {
            let clean = scanner.findings(in: data).isEmpty
            let text = String(decoding: data, as: UTF8.self)
            let metadataClean = privateValues.allSatisfy { !text.contains($0) }
            #expect(clean && metadataClean)
        }
        let allowedOffsets = try manifestOffsets(entries, archive: archive)
        let unexpected = scanner.findings(in: archive).contains {
            $0.kind != .hex64 || !allowedOffsets.contains($0.offset)
        }
        #expect(!unexpected)
    }

    private static func manifestOffsets(_ entries: [String: Data], archive: Data) throws -> Set<Int> {
        let manifest = try #require(entries["manifest.json"])
        let manifestRange = try #require(archive.range(of: manifest))
        let document = try #require(JSONSerialization.jsonObject(with: manifest) as? [String: Any])
        let hashes = try #require(document["entries"] as? [[String: String]])
        var allowedOffsets: Set<Int> = []
        for entry in hashes {
            let name = try #require(entry["name"]), digest = try #require(entry["sha256"])
            let payload = try #require(entries[name])
            let actual = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
            #expect(digest == actual)
            var start = manifest.startIndex
            while let range = manifest.range(of: Data(digest.utf8), in: start ..< manifest.endIndex) {
                allowedOffsets.insert(manifestRange.lowerBound + range.lowerBound)
                start = range.upperBound
            }
        }
        return allowedOffsets
    }

    private static func fixtureKey(_ name: String) throws -> SecretBytes {
        var data = try FixtureLoader.repository().data("keys/" + name)
        let source = try SecretBytes(wiping: &data)
        let range = try #require(source.withUnsafeBytes { raw -> Range<Int>? in
            var start = 0
            for end in raw.indices where raw[end] == 10 {
                if start < end, raw[start] != 35 {
                    return start ..< end
                }
                start = end + 1
            }
            return nil
        })
        let text = try SecretBytes(copying: source, range: range)
        let key = try PrivateKey(parsing: text, encoding: .base64)
        var raw = try SecretBytes(zeroedCount: 32); try key.encode(into: &raw)
        return raw
    }
}
