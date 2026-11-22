// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

private final class RecordingLogSink: ProviderLogSink {
    private let storage = Mutex<[String]>([])
    var lines: [String] {
        storage.withLock { $0 }
    }

    func write(_ line: String) {
        storage.withLock { $0.append(line) }
    }
}

/// Key material in each textual form an engine line could carry; built at run time, never stored as text.
private enum KeyForms {
    /// The private key FakeSecretLoader hands the engine.
    static let privateKey = Data(repeating: 3, count: 32)
    static let presharedKey = Data((0 ..< 32).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 1) })

    static func forms(_ key: Data) -> [String] {
        let base64 = key.base64EncodedString()
        let url = base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let hex = key.map { String(format: "%02x", $0) }.joined()
        return [base64, String(base64.dropLast()), url, hex]
    }

    static var all: [String] {
        forms(privateKey) + forms(presharedKey)
    }
}

private struct LogHarness {
    let clock = TestClock()
    let system: FakeProviderSystem
    let factory = RecordingEngineFactory()
    let sink = RecordingLogSink()
    let controller: ProviderController
    let profile: TunnelProfile

    init() throws {
        system = FakeProviderSystem(clock: clock)
        profile = try GoldenFixture.profile()
        let factory = factory
        controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: FakeResolver(),
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) }, logSink: sink,
        )
    }

    var engine: FakeEngine {
        factory.engines[factory.engines.count - 1]
    }

    func send(_ message: ProviderMessage) async throws -> ProviderReply {
        let data = try await #require(controller.handle(ProviderCodec.encode(message)))
        return try ProviderCodec.decode(ProviderReply.self, from: data)
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ProviderLogTests {
    @Test
    func `the sink gets lifecycle, path, reassert, failure and engine lines and no key material`() async throws {
        let h = try LogHarness()
        try await h.controller.startTunnel(profileID: h.profile.id)
        #expect(h.sink.lines == ["Tunnel starting", "Tunnel active"])
        await h.system.yieldPath(ProviderPath(satisfied: true, interfaceIndex: 7))
        await eventually { h.sink.lines.contains("Reasserting: pathChanged") }
        await h.engine.emit(.handshakeCompleted(peer: h.profile.peers[0].publicKey, at: h.clock.wallNow))
        await eventually { h.sink.lines.contains("Reassert ended: handshake completed") }
        for (index, form) in KeyForms.all.enumerated() {
            let message = "UAPI: private_key=\(form)\npeer '\(form)'"
            let level: EngineLogLine.Level = index.isMultiple(of: 2) ? .error : .info
            await h.engine.emit(log: EngineLogLine(level: level, message: message, date: h.clock.wallNow))
        }
        await eventually { h.sink.lines.count { $0.hasPrefix("Engine ") } == KeyForms.all.count }
        await h.engine.emit(.engine(.deviceClosed(.tunReadError)))
        await eventually { h.sink.lines.contains("Tunnel ended: engine error -9") }
        await h.controller.stopTunnel(reason: 1)
        let lines = h.sink.lines
        #expect(lines.contains("Path changed: interface 7"))
        #expect(lines.contains("Engine error: UAPI: (redacted) peer '(redacted)'"))
        #expect(lines.suffix(2).first?.hasPrefix("Tunnel stopping: reason 1 ") == true)
        #expect(lines.last == "Tunnel stopped")
        for line in lines {
            #expect(KeyForms.all.allSatisfy { !line.contains($0) })
            #expect(!line.contains("\n") && line.count <= 300)
        }
        // The `.logs` reply is no longer a placeholder: it returns the same lines.
        #expect(try await h.send(.logs(since: nil)) == .logs(lines))
        #expect(try await h.send(.logs(since: h.clock.wallNow.addingTimeInterval(1))) == .logs([]))
    }

    @Test
    func `a failed reload through the message ends the tunnel cleanly and logs it`() async throws {
        let h = try LogHarness()
        try await h.controller.startTunnel(profileID: h.profile.id)
        h.factory.faults.arm("up", error: EngineError.state)
        #expect(try await h.send(.reload(profileID: h.profile.id)) == .error(.engine(code: -8)))
        #expect(await h.system.cancels == [.engine(code: -8)])
        #expect(await h.system.settings.last == .some(nil))
        #expect(Array(h.sink.lines.suffix(2)) == ["Tunnel reloading", "Tunnel ended: engine error -8"])
        await h.controller.stopTunnel(reason: 1)
    }

    @Test
    func `the logs reply keeps only the newest lines`() async throws {
        let h = try LogHarness()
        try await h.controller.startTunnel(profileID: h.profile.id)
        for index in 0 ..< 300 {
            await h.engine.emit(log: EngineLogLine(level: .debug, message: "line \(index)", date: h.clock.wallNow))
        }
        await eventually { h.sink.lines.last == "Engine debug: line 299" }
        guard case let .logs(lines) = try await h.send(.logs(since: nil)) else { Issue.record("No logs reply"); return }
        #expect(lines.count == 256)
        #expect(lines.last == "Engine debug: line 299")
        await h.controller.stopTunnel(reason: 1)
    }
}

/// Token delimiters: any character outside ASCII letters, digits and `+/=_-` ends a run; a run of 40 or more is redacted.
private struct LogScrubTests {
    private static let base64 = KeyForms.privateKey.base64EncodedString()

    @Test(arguments: KeyForms.all)
    func `every key form is redacted between ordinary delimiters`(_ form: String) {
        #expect(ProviderLogText.scrub("key \(form) end") == "key (redacted) end")
        #expect(ProviderLogText.scrub("(\(form))") == "((redacted))")
        #expect(ProviderLogText.scrub("private_key=\(form)") == "(redacted)")
    }

    @Test
    func `a run shorter than a key is kept and the boundary is forty characters`() {
        let short = String(repeating: "a", count: 39)
        #expect(ProviderLogText.scrub(short) == short)
        #expect(ProviderLogText.scrub(short + "a") == "(redacted)")
        #expect(ProviderLogText.scrub("peer(AbCd…xYz) - Sending handshake") == "peer(AbCd…xYz) - Sending handshake")
    }

    @Test
    func `control characters and newlines become spaces`() {
        #expect(ProviderLogText.scrub("a\u{0}b\tc\r\nd\ne") == "a b c d e")
    }

    @Test
    func `truncation never exposes part of a key`() {
        let scrubbed = ProviderLogText.scrub(String(repeating: " ", count: 295) + Self.base64)
        #expect(scrubbed.count == 300)
        #expect(!scrubbed.contains(String(Self.base64.prefix(4))))
    }
}
