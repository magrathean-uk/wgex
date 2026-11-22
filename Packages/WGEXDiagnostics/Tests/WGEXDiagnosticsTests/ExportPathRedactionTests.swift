// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXDiagnostics
import WGEXEngineInterface
import WGEXTesting

/// The real controller, dispatcher and wire codec composed with the real diagnostics adapter (the symlinked daemon source).
/// Every entry of the exported ZIP is decoded and searched; a control run with redaction bypassed must fail the same search.
private struct ExportPathRedactionTests {
    /// Test material: fixture and random bytes only, never a real key.
    private struct Material {
        let privateKey: Data
        let preshared: Data
        let onDemandKey: Data
        let pfToken = "4503599627370497"
        let externalForm = Data((0 ..< 32).map { UInt8(($0 * 7 + 3) % 256) })
        let secondOwnerName = "Second owner private profile"
        let firstName = "First owner export profile"
        let onDemandName = "First owner on-demand profile"

        var secrets: [(name: String, bytes: Data)] {
            [("private", privateKey), ("preshared", preshared), ("onDemand", onDemandKey), ("externalForm", externalForm)]
        }

        /// What the export search looks for: the secrets plus the pf reference token's ASCII bytes, so its encodings and
        /// 12-character fragments are searched too (it is kept out of `secrets`, which the rig echoes into logs).
        var searched: [(name: String, bytes: Data)] {
            secrets + [("pfToken", Data(pfToken.utf8))]
        }

        /// The token as a number in hex, the other way a reference can be printed.
        var numericHex: [String] {
            let hex = String(UInt64(pfToken) ?? 0, radix: 16)
            return [hex, hex.uppercased()]
        }

        var searchedStrings: [String] {
            [pfToken] + numericHex + [secondOwnerName, firstName, onDemandName]
        }
    }

    private struct Finding: Hashable, CustomStringConvertible {
        let entry: String
        let secret: String
        let shape: String
        var description: String {
            "\(entry): \(secret) \(shape)"
        }
    }

    private struct Outcome {
        let entries: [String: Data]
        let material: Material
        let reply: Data
    }

    // MARK: Tests

    @Test
    func `export through the dispatcher and wire codec leaks no secret in any encoding`() async throws {
        let outcome = try await Self.export(bypassRedaction: false)
        #expect(outcome.entries.keys.contains { $0.hasPrefix("logs/") })
        #expect(outcome.entries.keys.contains { $0.contains("-pf-") })
        let found = Self.findings(
            in: outcome.entries,
            secrets: outcome.material.searched,
            strings: Self.privateStrings(outcome.material),
            fragmentStrings: outcome.material.numericHex,
        )
        #expect(found.isEmpty, "\(found.sorted { $0.description < $1.description })")
        #expect(outcome.entries.values.allSatisfy { !String(decoding: $0, as: UTF8.self).contains(outcome.material.secondOwnerName) })
        // The reply bytes themselves carry the archive: nothing readable in the wire frame either.
        let wire = Self.findings(
            in: ["reply": outcome.reply], secrets: outcome.material.searched, strings: Self.privateStrings(outcome.material),
            fragmentStrings: outcome.material.numericHex,
        )
        #expect(wire.isEmpty)
    }

    @Test
    func `the search detects an encoded pf token and a 12-character literal fragment`() throws {
        let material = Material(
            privateKey: Data(repeating: 1, count: 32),
            preshared: Data(repeating: 2, count: 32),
            onDemandKey: Data(repeating: 3, count: 32),
        )
        let token = Data(material.pfToken.utf8)
        let fragment = String(material.pfToken.dropFirst(2).prefix(12))
        #expect(fragment.count == 12 && fragment != material.pfToken)
        let leaks: [(String, String)] = [
            ("literal fragment", "pf reference \(fragment) held"),
            ("base64", "ref=" + token.base64EncodedString()),
            ("base64 fragment", String(token.base64EncodedString().dropFirst(3).prefix(12))),
            ("hex", token.map { String(format: "%02x", $0) }.joined()),
            ("numeric hex", String(UInt64(material.pfToken) ?? 0, radix: 16)),
        ]
        // Only a 12-character window of the numeric hex (not the whole literal, not the decimal token).
        let hexFragment = try String(#require(material.numericHex.first).dropFirst(1).prefix(12))
        #expect(hexFragment.count == 12 && !material.pfToken.contains(hexFragment))
        let allLeaks = leaks + [("numeric hex fragment", "ref \(hexFragment) held"), ("numeric HEX fragment", hexFragment.uppercased())]
        for (label, text) in allLeaks {
            let found = Self.findings(
                in: ["logs/x": Data(text.utf8)], secrets: material.searched, strings: material.searchedStrings,
                fragmentStrings: material.numericHex,
            )
            #expect(!found.isEmpty, "\(label) was not detected")
        }
        let clean = Self.findings(
            in: ["logs/x": Data("pf reference redacted, 0123456789".utf8)],
            secrets: material.searched,
            strings: material.searchedStrings,
            fragmentStrings: material.numericHex,
        )
        #expect(clean.isEmpty, "\(clean)")
    }

    #if DEBUG
        @Test
        func `a control run with redaction bypassed fails the same search`() async throws {
            let outcome = try await Self.export(bypassRedaction: true)
            let found = Self.findings(
                in: outcome.entries,
                secrets: outcome.material.searched,
                strings: Self.privateStrings(outcome.material),
                fragmentStrings: outcome.material.numericHex,
            )
            // The planted pf, routes and DNS sections carry the same secrets, so the findings must sit in the exported logs entry.
            let inLogs = found.filter { $0.entry.hasPrefix("logs/") }
            #expect(!outcome.entries.keys.filter { $0.hasPrefix("logs/") }.isEmpty)
            #expect(inLogs.contains { $0.secret == "private" }, "logs entry findings: \(inLogs)")
            #expect(inLogs.contains { $0.secret == "preshared" }, "logs entry findings: \(inLogs)")
            #expect(inLogs.contains { $0.secret == "onDemand" }, "logs entry findings: \(inLogs)")
            #expect(inLogs.contains { $0.secret == outcome.material.firstName })
            #expect(found.contains { $0.secret == outcome.material.firstName })
            // Isolation does not depend on redaction: the second owner's ring never reaches the first owner's bundle.
            #expect(!found.contains { $0.secret == outcome.material.secondOwnerName })
        }
    #endif
}

extension ExportPathRedactionTests {
    // MARK: Search

    private static func shapes(of bytes: Data) -> [(String, String)] {
        let base64 = bytes.base64EncodedString()
        let url = base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return [
            ("base64", base64), ("base64-unpadded", base64.replacingOccurrences(of: "=", with: "")),
            ("base64url", url), ("base64url-unpadded", url.replacingOccurrences(of: "=", with: "")),
            ("hex", hex), ("HEX", hex.uppercased()),
        ]
    }

    /// Any whole secret or any 12-character window of one, in every encoding, also across removed line breaks.
    private static func findings(
        in entries: [String: Data],
        secrets: [(name: String, bytes: Data)],
        strings: [String],
        fragmentStrings: [String] = [],
    ) -> Set<Finding> {
        var found: Set<Finding> = []
        for (entry, data) in entries {
            let text = String(decoding: data, as: UTF8.self)
            let compact = text.filter { !$0.isNewline && !$0.isWhitespace }
            func contains(_ needle: String) -> Bool {
                text.contains(needle) || compact.contains(needle)
            }
            for (name, bytes) in secrets {
                for (shape, encoded) in shapes(of: bytes) {
                    let characters = Array(encoded.replacingOccurrences(of: "=", with: ""))
                    for start in 0 ... max(0, characters.count - 12) where characters.count >= 12 {
                        if contains(String(characters[start ..< start + 12])) {
                            found.insert(Finding(entry: entry, secret: name, shape: shape)); break
                        }
                    }
                }
                for start in 0 ... max(0, bytes.count - 12) where data.range(of: bytes[start ..< start + 12]) != nil {
                    found.insert(Finding(entry: entry, secret: name, shape: "raw")); break
                }
            }
            for value in strings where contains(value) {
                found.insert(Finding(entry: entry, secret: value, shape: "literal"))
            }
            for value in fragmentStrings {
                let characters = Array(value)
                for start in 0 ... max(0, characters.count - 12) where characters.count >= 12 {
                    if contains(String(characters[start ..< start + 12])) {
                        found.insert(Finding(entry: entry, secret: value, shape: "literal fragment")); break
                    }
                }
            }
        }
        return found
    }

    // MARK: Rig

    private static func fixtureKey(_ name: String) throws -> Data {
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
        let key = try PrivateKey(parsing: SecretBytes(copying: source, range: range), encoding: .base64)
        var raw = try SecretBytes(zeroedCount: 32); try key.encode(into: &raw)
        return raw.withUnsafeBytes { Data($0) }
    }

    private static func secretBytes(_ data: Data) throws -> SecretBytes {
        var copy = data
        return try SecretBytes(wiping: &copy)
    }

    private static func wire(privateKey: Data, preshared: (Data, PublicKey)? = nil) throws -> Data {
        var writer = try SecretsWireWriter(privateKey: secretBytes(privateKey))
        if let (key, peer) = preshared {
            try writer.appendPresharedKey(secretBytes(key), for: peer)
        }
        return try writer.finish().withUnsafeBytes { Data($0) }
    }

    private static func profile(
        _ name: String, key: Data, peer: Data, preshared: Bool, onDemand: Bool,
    ) throws -> TunnelProfile {
        var profile = TunnelProfile(name: name)
        profile.interface = try InterfaceConfiguration(
            addresses: [IPAddressRange("10.77.0.2/32")],
            dns: [DNSServer("10.77.0.1")],
            publicKey: PrivateKey(bytes: secretBytes(key)).publicKey(),
        )
        profile.peers = try [PeerConfiguration(
            publicKey: PrivateKey(bytes: secretBytes(peer)).publicKey(),
            hasPresharedKey: preshared,
            allowedIPs: [IPAddressRange("0.0.0.0/0")],
            endpoint: Endpoint("peer.example.test:51820"),
        )]
        profile.protection.ipv6Policy = .blockOutside
        if preshared, let peer = profile.peers.first?.publicKey {
            profile.secrets = SecretReferences(privateKey: .daemonStore(id: UUID()), presharedKeys: [peer: .daemonStore(id: UUID())])
        }
        if onDemand {
            profile.onDemand = .interfaces(.ethernetOnly)
        }
        return profile
    }

    private static func lines(for bytes: Data) -> [String] {
        let base64 = bytes.base64EncodedString()
        let url = base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        let limit = DaemonDiagnosticsAdapter.engineLineByteLimit
        return [
            "handshake from peer \(base64) accepted", "relay \(url)", "uapi private_key=\(hex)", "UPPER \(hex.uppercased())",
            "split begins \(base64.prefix(20))", "\(base64.dropFirst(20)) split ends",
            "fragment \(base64.dropFirst(7).prefix(14)) only",
            // The key starts 20 bytes before the stored-line limit, so the cut falls inside it.
            String(repeating: ".", count: limit - 20) + base64,
            String(repeating: ".", count: limit - 40) + hex,
        ]
    }

    private static func send(_ transport: InMemoryXPCTransport, _ request: Request, authorization: Data? = nil, secrets: Data? = nil)
        async throws -> (reply: Reply, raw: Data)
    {
        let raw = try await transport.send(Envelope(authorization: authorization, body: request).encoded(), secrets: secrets)
        return try (WireCodec.decode(Reply.self, from: raw), raw)
    }

    private static func connect(_ uid: UInt32, _ composition: DaemonComposition) async throws -> InMemoryXPCTransport {
        let transport = InMemoryXPCTransport(
            daemon: composition.dispatcher,
            peer: VerifiedPeerIdentity(uid: uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        guard case .hello = try await send(transport, .hello(clientVersion: "test", clientBuild: 11)).reply else {
            throw ExportFailure.unexpectedReply
        }
        return transport
    }

    // swiftlint:disable:next function_body_length
    private static func export(bypassRedaction: Bool) async throws -> Outcome {
        var random = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
        let material = try Material(
            privateKey: fixtureKey("client1.key"), preshared: random, onDemandKey: fixtureKey("client2.key"),
        )
        random.resetBytes(in: 0 ..< random.count)
        let first = try profile(material.firstName, key: material.privateKey, peer: material.onDemandKey, preshared: true, onDemand: false)
        let onDemand = try profile(
            material.onDemandName, key: material.onDemandKey, peer: material.privateKey, preshared: false, onDemand: true,
        )
        let other = try profile(
            material.secondOwnerName, key: material.onDemandKey, peer: material.privateKey, preshared: false, onDemand: false,
        )
        // The key material the daemon registered is echoed. The pf token and the external form are only set on the daemon and
        // searched for: no daemon path echoes them, so planting them would test an invented leak.
        let echoed = material.secrets.filter { $0.name != "externalForm" }
        let nameLines = [material.firstName, material.onDemandName].map { "profile \($0) changed" }
        let leakText = (echoed.flatMap { lines(for: $0.bytes) } + nameLines).joined(separator: "\n")
        let adapter = DaemonDiagnosticsAdapter(sections: {
            [.init(kind: .pf, text: leakText), .init(kind: .routes, text: leakText), .init(kind: .dns, text: leakText)]
        })
        let root = try StateDirectory.temporaryRoot().appendingPathComponent("wgex-export-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try StateDirectory(root: root)
        let store = try DaemonSecretStore(
            directory: directory, keyProvider: InMemoryDaemonKeyProvider(key: secretBytes(fixtureKey("psk1.key"))),
            observeBundle: { try adapter.registerSecretWire($0) },
        )
        let registry = try ProfileRegistry(
            repository: DirectoryProfileRepository(directory: directory), secrets: store, bundles: store,
            profileRegistered: { adapter.register($0) },
        )
        let ports = ExportPorts(pfToken: material.pfToken)
        let controller = try TunnelController(
            registry: registry, secureInstall: ExportVerifiedInstall(), journal: DaemonJournal(directory: directory), secrets: store,
            ports: DaemonPorts(
                engineFactory: ports, routes: ports, dns: ports, policy: ports, resolver: ports, device: ports, verifier: ports,
                reality: ports,
            ),
            underlay: UnderlaySnapshot(v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"]),
            diagnostics: adapter,
        )
        let composition = DaemonComposition(
            controller: controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }, hasAdminRight: { _, _ in true }),
            statusJournal: StatusPublicationJournal(directory: directory),
        )
        let owner = try await connect(501, composition), stranger = try await connect(502, composition)
        for (transport, item) in [(owner, first), (owner, onDemand), (stranger, other)] {
            let reply = try await send(transport, .installProfileCAS(item, expectedRevision: nil)).reply
            #expect(reply == .profileRevision(1), "\(item.name): \(reply)")
        }
        let peer = try PrivateKey(bytes: secretBytes(material.onDemandKey)).publicKey()
        // The on-demand bundle is stored by the daemon until the profile is disarmed.
        let armed = try await send(
            owner, .armOnDemand(profileID: onDemand.id, hasSecrets: true),
            secrets: wire(privateKey: material.onDemandKey),
        ).reply
        #expect(armed == .ok, "arm: \(armed)")
        // The authorisation external form crosses the dispatcher on an admin-right request.
        _ = try await send(owner, .performSecureInstall, authorization: material.externalForm).reply
        let started = try await send(
            owner, .startIntent(profileID: first.id, transport: nil, hasSecrets: true),
            secrets: wire(privateKey: material.privateKey, preshared: (material.preshared, peer)),
        ).reply
        guard case let .started(generation) = started else {
            Issue.record("start: \(started)"); throw ExportFailure.unexpectedReply
        }
        let engine = try #require(await ports.engine)
        let engineLines = echoed.flatMap { lines(for: $0.bytes) } + nameLines
        for line in engineLines {
            await engine.emit(log: EngineLogLine(level: .error, message: line, date: Date()))
            adapter.recordEngine(line, date: Date(), profileID: nil)
        }
        adapter.recordEngine("\(material.secondOwnerName) \(material.privateKey.base64EncodedString())", date: Date(), profileID: other.id)
        var received = false
        for _ in 0 ..< 500 {
            let seen = try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: [first.id]).filter { $0.profileID == first.id }
            if seen.count >= engineLines.count {
                received = true
                break
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(received, "engine log lines never reached the adapter ring")
        let request = DiagnosticsRequest(includeLogs: true, since: nil, profileIDs: [first.id, onDemand.id, other.id])
        #if DEBUG
            let exported = try await Redactor.$bypassForTesting.withValue(bypassRedaction) {
                try await send(owner, .diagnostics(request))
            }
        #else
            precondition(!bypassRedaction, "the redaction bypass is not compiled outside DEBUG")
            let exported = try await send(owner, .diagnostics(request))
        #endif
        guard case let .diagnostics(bundle) = exported.reply else { throw ExportFailure.unexpectedReply }
        _ = try await send(owner, .stop(profileID: first.id, reason: .userRequested))
        withExtendedLifetime(generation) {}
        return try Outcome(entries: ZIPInspection.entries(bundle.archive), material: material, reply: exported.raw)
    }

    private enum ExportFailure: Error { case unexpectedReply }

    private static func privateStrings(_ material: Material) -> [String] {
        material.searchedStrings
    }
}
