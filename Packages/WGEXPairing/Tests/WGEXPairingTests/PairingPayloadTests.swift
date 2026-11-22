// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Testing
import WGEXCore
@testable import WGEXPairing

private struct PairingPayloadTests {
    @Test(arguments: [-1, 0, 1])
    func `serialised profile fits the encrypted frame cap exactly`(offset: Int) async throws {
        let rig = try PairingRig.make(manual: false)
        try await rig.handshake(); try await rig.confirm()
        let configuration = try sizedProfile(PairingFrame.maximumProfileLength + offset)
        if offset <= 0 {
            try await rig.sender.sendProfile(configuration)
            try await rig.tv.advance(); try await rig.sender.advance()
            #expect(await rig.sink.stored == 1)
        } else {
            do { try await rig.sender.sendProfile(configuration); Issue.record("Expected frame cap rejection") }
            catch let error as PairingError { #expect(error == .frameOverflow) }

            #expect(await rig.sink.stored == 0)
            await rig.tv.cancel()
        }
    }

    @Test
    func `ciphertext substitution is rejected with no storage`() async throws {
        let rig = try PairingRig.make()
        try await rig.handshake(); try await rig.confirm()
        await rig.senderWire.setHook { frame in
            var replacement = frame
            if !replacement.isEmpty {
                replacement[replacement.count - 1] ^= 1
            }
            return .substitute(replacement)
        }
        try await rig.sender.sendProfile(PairingFixtures.profile())
        await expectPairingError(.authenticationFailed) { try await rig.tv.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `authenticated but invalid wg quick is rejected by the standard parser`() async throws {
        let rig = try PairingRig.make()
        try await rig.handshake(); try await rig.confirm()
        // A skeleton has valid keys but no interface address or peers; full parser diagnostics reject it.
        var configuration = try PairingFixtures.profile()
        configuration.profile.interface.addresses = []
        configuration.profile.peers = []
        try await rig.sender.sendProfile(configuration)
        await expectPairingError(.invalidProfile) { try await rig.tv.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `ciphertext replay into another session fails aad and context binding`() async throws {
        let first = try PairingRig.make()
        try await first.handshake(); try await first.confirm()
        try await first.sender.sendProfile(PairingFixtures.profile())
        let replay = try await first.tvWire.receive()
        await first.tv.cancel(); await first.sender.cancel()
        let second = try PairingRig.make()
        try await second.handshake(); try await second.confirm()
        try await second.senderWire.send(replay)
        await expectPairingError(.authenticationFailed) { try await second.tv.advance() }
        #expect(await first.sink.stored == 0); #expect(await second.sink.stored == 0)
        await second.tv.cancel(); await second.sender.cancel()
    }

    @Test
    func `forged sender confirmation and early ciphertext are rejected`() async throws {
        let rig = try PairingRig.make()
        try await rig.handshake()
        let sas = try #require(await rig.tv.shortAuthenticationString)
        try await rig.tv.confirmSAS(sas, accepted: true)
        try await rig.senderWire.send(PairingMessage(.sasConfirm, [Data([1]), Data(repeating: 0, count: 32)]).encoded())
        await expectPairingError(.authenticationFailed) { try await rig.tv.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
        let early = try PairingRig.make()
        try await early.handshake()
        let value = try #require(await early.tv.shortAuthenticationString)
        try await early.tv.confirmSAS(value, accepted: true)
        try await early.senderWire.send(PairingMessage(.sealedProfile, [Data(repeating: 0, count: 16)]).encoded())
        await expectPairingError(.unexpectedMessage) { try await early.tv.advance() }
        #expect(await early.sink.stored == 0)
        await early.tv.cancel(); await early.sender.cancel()
    }

    @Test
    func `forged storage result cannot report success`() async throws {
        let rig = try PairingRig.make()
        try await rig.handshake(); try await rig.confirm()
        try await rig.sender.sendProfile(PairingFixtures.profile())
        try await rig.tvWire.send(PairingMessage(.result, [Data(repeating: 0, count: 32)]).encoded())
        await expectPairingError(.authenticationFailed) { try await rig.sender.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    private func sizedProfile(_ target: Int) throws -> ParsedConfiguration {
        var configuration = try PairingFixtures.profile()
        let range = try IPAddressRange("2001:db8:abcd:1234:5678:90ab:cdef:1234/128")
        configuration.profile.peers[0].allowedIPs = [range]
        let base = try serialiseWgQuick(configuration.profile, secrets: configuration.secrets).byteCount
        let width = range.stringRepresentation.utf8.count + 2 // comma and space
        let repeats = (target - base - 16) / width
        configuration.profile.peers[0].allowedIPs.append(contentsOf: repeatElement(range, count: repeats))
        configuration.profile.interface.searchDomains = ["a"]
        let current = try serialiseWgQuick(configuration.profile, secrets: configuration.secrets).byteCount
        configuration.profile.interface.searchDomains = [String(repeating: "a", count: target - current + 1)]
        let text = try serialiseWgQuick(configuration.profile, secrets: configuration.secrets)
        #expect(text.byteCount == target)
        return configuration
    }
}
