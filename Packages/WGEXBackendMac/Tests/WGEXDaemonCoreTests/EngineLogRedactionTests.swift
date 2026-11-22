// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXTesting

/// The Mac log view reads the daemon's `logs` reply. Engine (tunnel) and daemon lines enter the diagnostics rings raw and
/// leave only redacted: planted private and preshared keys, in every textual shape, never reach a returned line, and one
/// reply stays bounded inside the XPC payload limit.
private struct EngineLogRedactionTests {
    private struct Keys: ~Copyable {
        let privateBase64: String
        let presharedBase64: String
        let scanner: SecretScanner
        let wire: SecretBytes

        /// Registered keys (the profile's private key and a preshared key, as the secret store reports them) and an
        /// unregistered pair the redactor can only recognise by shape.
        init() throws {
            let privateKey = try ControllerHarness.testKey()
            var random = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
            let preshared = try SecretBytes(wiping: &random)
            var writer = try SecretsWireWriter(privateKey: privateKey)
            try writer.appendPresharedKey(preshared, for: PrivateKey(bytes: SecretBytes(parsing: privateKey)).publicKey())
            wire = try writer.finish()
            privateBase64 = privateKey.withUnsafeBytes { Data($0).base64EncodedString() }
            presharedBase64 = preshared.withUnsafeBytes { Data($0).base64EncodedString() }
            var scanner = SecretScanner(); scanner.register(privateKey); scanner.register(preshared)
            self.scanner = scanner
        }

        static func hex(_ base64: String) -> String {
            (Data(base64Encoded: base64) ?? Data()).map { String(format: "%02x", $0) }.joined()
        }

        static func url(_ base64: String) -> String {
            base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }

        var unregistered: [String] {
            (0 ..< 2).map { _ in Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) }).base64EncodedString() }
        }

        /// Every shape of every key, plus registered-key fragments the shape scan alone would miss.
        func shapes(_ extra: [String]) -> [String] {
            ([privateBase64, presharedBase64] + extra).flatMap { key in
                [
                    key, Self.url(key), Self.hex(key), "PrivateKey = \(key)", "PresharedKey=\(key)", "peer(\(key))",
                    String(key.prefix(42)),
                ]
            } + [privateBase64, presharedBase64].map { "fragment \($0.dropFirst(5).prefix(14)) end" }
        }

        func fragments(_ extra: [String]) -> [String] {
            ([privateBase64, presharedBase64] + extra).flatMap { key in
                [String(key.dropFirst(8).prefix(16)), String(Self.hex(key).dropFirst(8).prefix(24))]
            }
        }

        func assertClean(_ lines: [RedactedLogLine], extra: [String], sourceLocation: SourceLocation = #_sourceLocation) throws {
            let encoded = try WireCodec.encode(Reply.logs(lines))
            let text = lines.map { "\($0.category) \($0.message)" }.joined(separator: "\n") + String(decoding: encoded, as: UTF8.self)
            #expect(scanner.isClean(text), sourceLocation: sourceLocation)
            for fragment in fragments(extra) {
                #expect(!text.contains(fragment), sourceLocation: sourceLocation)
            }
        }
    }

    @Test
    func `planted keys in engine lines of every ring never leave the daemon unredacted`() async throws {
        let keys = try Keys()
        let extra = keys.unregistered
        let adapter = DaemonDiagnosticsAdapter()
        try adapter.registerSecretWire(keys.wire)
        let mine = UUID(), other = UUID()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        let shapes = keys.shapes(extra)
        for (index, shape) in shapes.enumerated() {
            let date = start.addingTimeInterval(Double(index))
            adapter.recordEngine("Received handshake \(shape) from peer", date: date, profileID: mine)
            adapter.recordEngine(shape, date: date, profileID: nil)
            // Over the stored bound, with the key straddling the cut.
            adapter.recordEngine(
                String(repeating: ".", count: DaemonDiagnosticsAdapter.engineLineByteLimit - 30) + shape,
                date: date,
                profileID: mine,
            )
            adapter.recordEngine("other owner \(shape)", date: date, profileID: other)
        }
        // A daemon line sits in the same rings.
        let status = TunnelStatus(phase: .idle, protection: .unprotected, transport: nil, health: .idle, recentEvents: [])
        let daemonLine = await adapter.record(.init(event: .status(status), profileID: mine, ownerUID: 501))
        #expect(daemonLine?.message == "Tunnel status changed")

        let lines = try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: [mine])
        #expect(lines.count == shapes.count * 3 + 1)
        #expect(lines.allSatisfy { $0.profileID == nil || $0.profileID == mine })
        #expect(!lines.contains { $0.message.hasPrefix("other owner") })
        #expect(lines.contains { $0.category == "engine" && $0.message.hasPrefix("Received handshake") })
        #expect(lines.contains { $0.category == "daemon" && $0.message == "Tunnel status changed" })
        try keys.assertClean(lines, extra: extra)
        let bundle = try await adapter.bundle(.init(includeLogs: true, since: nil, profileIDs: [mine]), visibleProfileIDs: [mine])
        // The archive is a stored (uncompressed) ZIP, so its bytes are the entries' text. Its manifest carries SHA-256
        // digests (64 hex characters), so only registered secrets and planted fragments are searched here.
        #expect(!keys.scanner.findings(in: bundle.archive).contains { $0.kind == .registeredSecret })
        for fragment in keys.fragments(extra) {
            #expect(bundle.archive.range(of: Data(fragment.utf8)) == nil)
        }
    }

    @Test
    func `one logs reply is bounded in lines, line length and bytes`() async throws {
        let adapter = DaemonDiagnosticsAdapter()
        let id = UUID()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        for index in 0 ..< 800 {
            adapter.recordEngine(
                "line \(index) " + String(repeating: "é", count: 3000),
                date: start.addingTimeInterval(Double(index)),
                profileID: id,
            )
        }
        let lines = try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: [id])
        #expect(!lines.isEmpty && lines.count <= 512)
        #expect(lines.allSatisfy { $0.message.utf8.count <= DaemonDiagnosticsAdapter.replyLineByteLimit })
        #expect(lines.last?.message.hasPrefix("line 799 ") == true)
        #expect(zip(lines, lines.dropFirst()).allSatisfy { $0.date <= $1.date })
        #expect(try WireCodec.encode(Reply.logs(lines)).count <= DaemonDispatcher.maximumPayloadSize)
        let since = try await adapter.logs(since: start.addingTimeInterval(790), limit: 512, visibleProfileIDs: [id])
        #expect(since.count == 10)
        #expect(try await adapter.logs(since: nil, limit: 5000, visibleProfileIDs: [id]).count <= 512)
        #expect(try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: []).isEmpty)
    }

    @Test
    func `the controller forwards the running engine's log lines to the profile's ring only`() async throws {
        let keys = try Keys()
        let adapter = DaemonDiagnosticsAdapter()
        try adapter.registerSecretWire(keys.wire)
        let harness = try ControllerHarness(diagnostics: adapter); try await harness.install()
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        await harness.ports.useEngine(engine)
        _ = try await harness.start()
        await engine.emit(log: EngineLogLine(level: .info, message: "Interface state was Down, requested Up", date: Date()))
        await engine.emit(log: EngineLogLine(level: .error, message: "key \(keys.privateBase64) psk \(keys.presharedBase64)", date: Date()))
        var lines: [RedactedLogLine] = []
        for _ in 0 ..< 500 {
            lines = try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: [harness.profile.id])
                .filter { $0.category == "engine" }
            if lines.count == 2 {
                break
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(lines.count == 2)
        #expect(lines.allSatisfy { $0.profileID == harness.profile.id })
        #expect(lines.first?.message == "Interface state was Down, requested Up")
        try keys.assertClean(lines, extra: [])
        #expect(try await adapter.logs(since: nil, limit: 512, visibleProfileIDs: []).allSatisfy { $0.category != "engine" })
    }
}
