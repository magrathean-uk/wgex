// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
import WGEXTesting

private struct GeneratedFixtureTests {
    @Test
    func `examples generate independent valid keypairs and wipe parser input`() throws {
        var firstBytes = try GeneratedFixture.configurationBytes()
        var secondBytes = try GeneratedFixture.configurationBytes()
        let first = try parseWgQuick(&firstBytes)
        let second = try parseWgQuick(&secondBytes)
        #expect(firstBytes.allSatisfy { $0 == 0 })
        #expect(secondBytes.allSatisfy { $0 == 0 })
        let independent = first.profile.interface.publicKey != second.profile.interface.publicKey
        #expect(independent)
        let peer = try #require(first.profile.peers.first)
        let independentPeer = peer.publicKey != first.profile.interface.publicKey
        #expect(independentPeer)
        #expect(!first.diagnostics.contains { $0.severity == .error })
        var raw = try SecretBytes(zeroedCount: 32)
        try first.secrets.withKey(first.profile.secrets.privateKey) { source in
            raw.withUnsafeMutableBytes { $0.copyMemory(from: source) }
        }
        let key = try PrivateKey(bytes: raw)
        let derived = try key.publicKey() == first.profile.interface.publicKey
        #expect(derived)
        #expect(peer.endpoint?.host == "vpn.example.invalid")
    }
}
