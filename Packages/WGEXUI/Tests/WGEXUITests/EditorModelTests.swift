// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct EditorModelTests {
    private func editor() throws -> ProfileEditorModel {
        let parsed = try EditorFixtures.parsed()
        return try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
    }

    @Test
    func `Save requires a key addresses peers and zero errors`() throws {
        let empty = ProfileEditorModel()
        #expect(!empty.canSave)
        #expect(Set(empty.diagnostics.map(\.diagnostic.code)).isSuperset(of: [.invalidKey, .noAddresses, .noPeers, .limitExceeded]))
        let model = try editor()
        #expect(model.canSave)
        model.draft.protection.dnsPolicy = .systemDefault
        #expect(model.canSave)
        #expect(model.diagnostics.contains { $0.diagnostic.severity == .warning })
        model.draft.mtu = "9001"
        #expect(!model.canSave)
        #expect(throws: (any Error).self) { _ = try model.validatedProfile() }
    }

    @Test
    func `every diagnostic code has an explicit badge mapping`() {
        let mappings: [(ConfigDiagnostic.Code, Set<EditorField>)] = [
            (ConfigDiagnostic.Code.unknownKey, Set<EditorField>([.summary])),
            (.ignoredHook, [.summary]), (.amneziaField, [.summary]), (.duplicateKey, [.summary]),
            (.unsupportedSetting, [.summary]), (.invalidDNS, [.dns, .dnsPolicy]), (.invalidKeepalive, [.peers]),
            (.duplicatePeer, [.peers]), (.invalidCIDR, [.addresses]), (.invalidKey, [.privateKey]),
            (.invalidEndpoint, [.peers, .transport]), (.invalidPort, [.listenPort]), (.invalidMTU, [.mtu]),
            (.limitExceeded, [.name, .addresses, .dns, .peers]), (.controlCharacter, [.name, .searchDomains, .dnsPolicy]),
            (.dnsOutsideAllowedIPs, [.dns, .dnsPolicy]), (.noAddresses, [.addresses]), (.noPeers, [.peers]),
            (.ipv6PolicyRequired, [.ipv6Policy]), (.keyInUseElsewhere, [.privateKey]), (.carrierRequiresSinglePeer, [.peers]),
            (.keepaliveClampedByCarrier, [.peers, .transport]), (.exclusionPortEphemeral, [.exclusions]),
        ]
        #expect(Set(mappings.map(\.0)) == Set(ConfigDiagnostic.Code.allCases))
        for (code, fields) in mappings {
            #expect(ProfileEditorModel.defaultFields(for: code) == fields)
        }
    }

    @Test
    func `field initialisers retain invalid input and target the correct badges`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.draft.addresses = "10.0.0.1/33"
        model.draft.dns = "resolver.example"
        model.draft.listenPort = "+1"
        model.draft.mtu = "-1"
        model.draft.peers[0].publicKey = "bad"
        model.draft.peers[0].endpoint = "[bad]:99"
        model.draft.peers[0].allowedIPs.add("::/129")
        model.draft.peers[0].keepalive = "65536"
        for field in [EditorField.addresses, .dns, .listenPort, .mtu, .publicKey(id), .endpoint(id), .allowedIPs(id), .keepalive(id)] {
            #expect(!model.diagnostics(for: field).isEmpty)
        }
        #expect(model.draft.addresses == "10.0.0.1/33")
        #expect(!model.canSave)
    }

    @Test
    func `core cross field rules reach the live summary`() throws {
        let model = try editor()
        model.draft.name = "\n"
        model.draft.searchDomains = "\n"
        model.draft.protection.dnsPolicy = .split([])
        model.draft.addresses = "10.0.0.2/32"
        model.draft.peers[0].allowedIPs.setAllTraffic()
        model.draft.protection.ipv6Policy = .tunnel
        model.draft.peers.append(model.draft.peers[0])
        let codes = Set(model.diagnostics.map(\.diagnostic.code))
        #expect(codes.isSuperset(of: [.controlCharacter, .invalidDNS, .ipv6PolicyRequired, .duplicatePeer]))
        var profile = try EditorFixtures.parsed().profile
        profile.schemaVersion = 99
        let unsupported = ProfileEditorModel(profile: profile)
        #expect(unsupported.diagnostics.contains { $0.diagnostic.code == .unknownKey })
    }

    @Test
    func `dirty tracking reverses ordinary edits and confirms discard`() throws {
        let model = try editor()
        #expect(!model.isDirty)
        #expect(model.requestDiscard())
        let original = model.draft
        model.draft.name = "Changed"
        #expect(model.isDirty)
        #expect(!model.requestDiscard())
        #expect(model.showsDiscardConfirmation)
        #expect(try model.validatedProfile().original == nil)
        model.draft = original
        #expect(!model.isDirty)
        model.generateKeypair()
        #expect(model.isDirty)
        model.markSaved()
        #expect(!model.isDirty)
    }

    @Test
    func `generated keypair derives the displayed public key`() throws {
        let model = try editor()
        model.generateKeypair()
        let secrets = try model.makeSecrets()
        let profile = try model.validatedProfile()
        let derived = try secrets.withKey(profile.secrets.privateKey) { raw in
            try PrivateKey(bytes: SecretBytes(copying: raw)).publicKey()
        }
        #expect(derived == model.publicKey)
    }

    @Test
    func `peers reorder with stable identity and helpers edit the exported routes`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.addPeer()
        let second = try #require(model.draft.peers.last?.id)
        model.movePeers(from: IndexSet(integer: 0), to: 2)
        #expect(model.draft.peers.map(\.id) == [second, id])
        model.allTraffic(peerID: id)
        #expect(model.draft.peers[1].allowedIPs.routesAllTraffic)
        model.excludePrivateNetworks(peerID: id)
        #expect(model.draft.peers[1].allowedIPs.privateNetworkExclusion(dnsServers: ["10.77.0.1", "fd77:77::1"]) == .on)
        #expect(model.draft.peers[1].allowedIPs.texts.contains("::/0"))
        model.removePeer(id: second)
        #expect(model.canSave)
        let profile = try model.validatedProfile()
        #expect(profile.peers[0].allowedIPs.count > 2)
    }

    @Test
    func `descriptions and reflection never expose key bytes`() throws {
        let model = try editor()
        let printable = [
            model.description,
            String(describing: model),
            String(reflecting: model),
            String(describing: Mirror(reflecting: model)),
        ]
        for text in printable {
            let leaked = try EditorFixtures.containsSecret(text); #expect(!leaked)
        }
        #expect(Mirror(reflecting: model).children.isEmpty)
    }
}
