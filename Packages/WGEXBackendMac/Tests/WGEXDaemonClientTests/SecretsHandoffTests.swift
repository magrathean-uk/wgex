// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
@testable import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol
import WGEXProfileStore

private struct SecretsHandoffTests {
    private static func representations(_ bytes: Data) -> [Data] {
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return [bytes, bytes.base64EncodedData(), Data(hex.utf8), Data(hex.uppercased().utf8)]
    }

    @Test(arguments: 1 ... 16)
    func `fixture keys stay outside every envelope and land in wiped SecretBytes`(seed: Int) async throws {
        let service = ClientService()
        await service.expectSeed(seed)
        let store = InMemorySecretStore()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let transport = RecordingClientTransport(dispatcher)
        let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10, secretStore: store)
        let account = SecretID(profileID: service.id, kind: .privateKey)
        let peer = try PublicKey(rawValue: Data(repeating: 0x55, count: 32))
        let pskAccount = SecretID(profileID: service.id, kind: .presharedKey)
        var fixture = Data((0 ..< 32).map { UInt8(truncatingIfNeeded: seed * 7 + $0) })
        let patterns = Self.representations(fixture) + Self.representations(Data(repeating: 0xA5, count: 32))
        let key = try SecretBytes(wiping: &fixture)
        try await store.store(key, for: account)
        var psk = try SecretBytes(zeroedCount: 32)
        _ = psk.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0xA5) }
        try await store.store(psk, for: pskAccount)
        await client.setSecretReferences(.init(privateKey: account, presharedKeys: [peer: pskAccount]), for: service.id)
        let reports = Mutex<[SecretBytes.WipeReport]>([])
        try await SecretBytes.$wipeObserver.withValue({ report in reports.withLock { $0.append(report) } }) {
            try await client.start(service.id, transport: nil)
        }
        #expect(await client.lastGeneration == Generation(rawValue: 77))
        #expect(await service.secretStarts == 1)
        #expect(await service.lastPrivateKeyMatches)
        let envelopes = await transport.envelopes
        #expect(envelopes.count >= 4)
        #expect(envelopes.allSatisfy { envelope in patterns.allSatisfy { envelope.range(of: $0) == nil } })
        #expect(reports.withLock { !$0.isEmpty && $0.allSatisfy(\.isZeroed) })
        #expect(await transport.requests.first?.kind == .hello)
        await client.disconnect()
    }

    @Test
    func `CLI start obtains secrets only from same uid console app callback`() async throws {
        let service = ClientService()
        let store = InMemorySecretStore()
        let dispatcher = DaemonDispatcher(
            service: service,
            daemonVersion: "1",
            daemonBuild: 10,
            minimumClientBuild: 5,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let appTransport = RecordingClientTransport(dispatcher)
        let app = DaemonClient(transport: appTransport, clientVersion: "1", clientBuild: 10, secretStore: store)
        let account = SecretID(profileID: service.id, kind: .privateKey)
        var key = try SecretBytes(zeroedCount: 32)
        _ = key.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0xA5) }
        try await store.store(key, for: account)
        await app.setSecretReferences(.init(privateKey: account), for: service.id)
        _ = try await app.connect()
        let cliTransport = RecordingClientTransport(dispatcher)
        let cli = DaemonClient(transport: cliTransport, clientVersion: "1", clientBuild: 10)
        let reply = try await cli.request(.startIntent(profileID: service.id, transport: nil, hasSecrets: false))
        #expect(reply == .started(Generation(rawValue: 77)))
        #expect(await service.lastPrivateKeyMatches)
        #expect(await !cliTransport.secretsObserved)
        await #expect(throws: DaemonError.secretsUnavailable) { try await appTransport.askForSecrets(UUID()) }
        await app.disconnect()
        await cli.disconnect()
    }
}
