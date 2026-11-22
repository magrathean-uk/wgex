// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct EditorBoundaryTests {
    @Test(arguments: [
        ConfigDiagnostic.Code.unknownKey, .duplicatePeer, .invalidCIDR, .invalidKey, .invalidEndpoint, .invalidPort,
        .invalidMTU, .limitExceeded, .controlCharacter, .dnsOutsideAllowedIPs, .noAddresses, .noPeers, .ipv6PolicyRequired,
        .keyInUseElsewhere, .invalidDNS, .invalidKeepalive,
    ])
    func `every diagnostic reachable from a UDP editor has a live badge and summary`(_ code: ConfigDiagnostic.Code) throws {
        var parsed = try EditorFixtures.parsed()
        if code == .unknownKey {
            parsed.profile.schemaVersion = 99
        }
        let keys: Set<PublicKey> = code == .keyInUseElsewhere ? [parsed.profile.interface.publicKey] : []
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets, publicKeysInUse: keys)
        try trigger(code, model: model)
        let issues = model.diagnostics.filter { $0.diagnostic.code == code }
        #expect(!issues.isEmpty)
        #expect(issues.allSatisfy { !$0.fields.isEmpty })
        #expect(model.canSave == (code == .keyInUseElsewhere || code == .dnsOutsideAllowedIPs))
    }

    private func trigger(_ code: ConfigDiagnostic.Code, model: ProfileEditorModel) throws {
        if code == .invalidDNS {
            model.draft.dns = "not an address"
        }
        try triggerInterface(code, model: model)
        triggerPeer(code, model: model)
    }

    private func triggerInterface(_ code: ConfigDiagnostic.Code, model: ProfileEditorModel) throws {
        switch code {
        case .invalidCIDR: model.draft.addresses = "::/129"
        case .invalidKey:
            let bad = try SecretBytes(zeroedCount: 44)
            do { try model.setPrivateKey(bad) } catch { /* The field reports a safe validation error. */ }
        case .invalidPort: model.draft.listenPort = "65536"
        case .invalidMTU: model.draft.mtu = "1279"
        case .limitExceeded: model.draft.name = String(repeating: "a", count: 129)
        case .controlCharacter: model.draft.name = "bad\nname"
        case .dnsOutsideAllowedIPs: model.draft.protection.dnsPolicy = .systemDefault
        case .noAddresses: model.draft.addresses = ""
        default: break
        }
    }

    private func triggerPeer(_ code: ConfigDiagnostic.Code, model: ProfileEditorModel) {
        switch code {
        case .duplicatePeer:
            var other = PeerEditorDraft(); other.publicKey = model.draft.peers[0].publicKey
            model.draft.peers.append(other)
        case .invalidEndpoint: model.draft.peers[0].endpoint = "[bad]:123"
        case .invalidKeepalive: model.draft.peers[0].keepalive = "65536"
        case .noPeers: model.draft.peers = []
        case .ipv6PolicyRequired:
            model.draft.addresses = "10.0.0.2/32"
            model.draft.peers[0].allowedIPs.setAllTraffic()
            model.draft.protection.ipv6Policy = .tunnel
        default: break
        }
    }

    @Test(arguments: [UInt16(1280), 1500])
    func `numeric bounds are validated without clamping`(mtu: UInt16) throws {
        let parsed = try EditorFixtures.parsed()
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        model.draft.listenPort = "65535"; model.draft.mtu = String(mtu); model.draft.peers[0].keepalive = "65535"
        #expect(model.canSave)
        let profile = try model.validatedProfile()
        #expect(profile.interface.listenPort == 65535)
        #expect(profile.interface.mtu == mtu)
        #expect(profile.peers[0].persistentKeepalive == 65535)
        model.draft.peers[0].keepalive = "0"
        #expect(model.canSave)
        model.draft.listenPort = "0"
        #expect(!model.canSave)
    }

    @Test(arguments: ["1279", "1501", "9000", "65536", "+1280", "1280.0"])
    func `MTU editor retains and rejects values outside the Core contract`(text: String) throws {
        let parsed = try EditorFixtures.parsed()
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        model.draft.mtu = text
        #expect(!model.canSave)
        #expect(model.diagnostics(for: .mtu).contains { $0.code == .invalidMTU })
        #expect(model.draft.mtu == text)
    }

    @Test
    func `preshared key follows peer identity when its public key changes`() throws {
        let parsed = try EditorFixtures.parsed("multi-peer-split")
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        let id = try #require(model.draft.peers.first?.id)
        let oldKey = parsed.profile.peers[0].publicKey
        let reference = try #require(parsed.profile.secrets.presharedKeys[oldKey])
        var encoded = try SecretBytes(zeroedCount: 44)
        try parsed.secrets.withKey(reference) { raw in
            try encoded.withUnsafeMutableBytes { try ByteCodec.encode(raw, into: $0, encoding: .base64) }
        }
        try model.setPresharedKey(encoded, peerID: id)
        #expect(!model.isDirty)
        let replacement = try PublicKey(rawValue: Data(repeating: 99, count: 32))
        model.draft.peers[0].publicKey = replacement.base64
        let profile = try model.validatedProfile()
        #expect(profile.secrets.presharedKeys[oldKey] == nil)
        #expect(profile.secrets.presharedKeys[replacement] == reference)
        let secrets = try model.makeSecrets()
        let equal = try secrets.withKey(reference) { new in
            try parsed.secrets.withKey(reference) { old in new.elementsEqual(old) }
        }
        #expect(equal)
        model.removePresharedKey(peerID: id)
        #expect(try !model.validatedProfile().peers[0].hasPresharedKey)
    }

    @Test
    func `saving an edited draft never re enables stale original export`() throws {
        let parsed = try EditorFixtures.parsed()
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        model.draft.mtu = model.draft.mtu == "1400" ? "1401" : "1400"
        #expect(model.isDirty)
        model.markSaved()
        #expect(!model.isDirty)
        #expect(try model.validatedProfile().original == nil)
    }
}
