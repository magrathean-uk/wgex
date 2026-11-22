// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import WGEXPairing

private struct PairingSASCommitmentTests {
    @Test
    func `SAS commitments are role session key and nonce bound`() {
        let key = Data(repeating: 1, count: 32); let nonce = Data(repeating: 2, count: 32)
        let baseline = PairingCrypto.nonceCommitment(sid: "one", key: key, nonce: nonce, role: "tv")
        #expect(baseline != PairingCrypto.nonceCommitment(sid: "two", key: key, nonce: nonce, role: "tv"))
        #expect(baseline != PairingCrypto.nonceCommitment(sid: "one", key: nonce, nonce: nonce, role: "tv"))
        #expect(baseline != PairingCrypto.nonceCommitment(sid: "one", key: key, nonce: key, role: "tv"))
        #expect(baseline != PairingCrypto.nonceCommitment(sid: "one", key: key, nonce: nonce, role: "sender"))
    }

    @Test
    func `altering the sender nonce after commitment fails before the SAS stage`() async throws {
        let rig = try PairingRig.make()
        await rig.senderWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .reveal else { return .pass }
            var fields = message.fields; fields[2][0] ^= 1
            guard let replacement = try? PairingFrame.encode(PairingMessage(.reveal, fields).encoded()) else { return .pass }
            return .substitute(replacement)
        }
        try await beforeSASReveal(rig)
        #expect(await rig.tv.attempts == 0); #expect(await rig.tv.shortAuthenticationString == nil)
        await expectPairingError(.commitmentMismatch) { try await rig.tv.advance() }
        #expect(await rig.sink.stored == 0); #expect(await rig.tv.attempts == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `dropping the final TV nonce cannot evade a SAS attempt`() async throws {
        let rig = try PairingRig.make()
        let reveals = Mutex(0)
        await rig.tvWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .reveal else { return .pass }
            let final = reveals.withLock { $0 += 1; return $0 == 2 }
            return final ? .drop : .pass
        }
        try await beforeSASReveal(rig)
        try await rig.tv.advance()
        #expect(await rig.tv.attempts == 1); #expect(await rig.tv.state == .awaitingConfirmation)
        #expect(await rig.sender.shortAuthenticationString == nil)
        let sas = try #require(await rig.tv.shortAuthenticationString)
        await expectPairingError(.rejected) { try await rig.tv.confirmSAS(sas, accepted: false) }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `changing the TV final nonce fails the precommitted challenge`() async throws {
        let rig = try PairingRig.make()
        let reveals = Mutex(0)
        await rig.tvWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .reveal else { return .pass }
            let final = reveals.withLock { $0 += 1; return $0 == 2 }
            guard final else { return .pass }
            var fields = message.fields; fields[2][0] ^= 1
            guard let replacement = try? PairingFrame.encode(PairingMessage(.reveal, fields).encoded()) else { return .pass }
            return .substitute(replacement)
        }
        try await beforeSASReveal(rig); try await rig.tv.advance()
        await expectPairingError(.commitmentMismatch) { try await rig.sender.advance() }
        #expect(await rig.tv.attempts == 1); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test
    func `encapsulation cannot be reselected after nonce commitments`() async throws {
        let rig = try PairingRig.make()
        try await beforeSASReveal(rig)
        _ = try await rig.tvWire.receive()
        let lateContext = try PairingMessage(.ack, [Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation])
        try await rig.senderWire.send(lateContext.encoded())
        await expectPairingError(.unexpectedMessage) { try await rig.tv.advance() }
        #expect(await rig.tv.attempts == 0); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    private func beforeSASReveal(_ rig: PairingRig) async throws {
        try await rig.start(); try await rig.tv.advance(); try await rig.sender.advance()
        try await rig.tv.advance(); try await rig.sender.advance(); try await rig.tv.advance()
        #expect(await rig.tv.state == .awaitingSASCommit)
        try await rig.sender.advance(); try await rig.tv.advance()
        #expect(await rig.tv.state == .awaitingSASReveal)
    }
}
