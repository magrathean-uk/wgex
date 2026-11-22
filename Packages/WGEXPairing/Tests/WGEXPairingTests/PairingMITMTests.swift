// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import WGEXPairing

private struct PairingMITMTests {
    @Test
    func `RT23 substituted QR key cannot authenticate the TV`() async throws {
        let rig = try PairingRig.make(manual: false)
        let replacement = try PairingInvitation(
            sessionID: rig.tv.invitation.sessionID,
            publicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
        )
        let attackerQR = try PairingQRCodec.decode(PairingQRCodec.encode(replacement))
        let sender = PairingSender(invitation: attackerQR, clock: rig.clock)
        try await rig.tv.start(transport: rig.tvWire); try await sender.start(transport: rig.senderWire)
        try await rig.tv.advance()
        await expectPairingError(.authenticationFailed) { try await sender.advance() }
        #expect(await rig.tv.attempts == 0); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test
    func `RT23 reveal substitution fails the commitment before SAS`() async throws {
        let rig = try PairingRig.make()
        let falseKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        await rig.tvWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .reveal,
                  let altered = try? PairingMessage(.reveal, [message.fields[0], falseKey, message.fields[2]]),
                  let replacement = try? PairingFrame.encode(altered.encoded()) else { return .pass }
            return .substitute(replacement)
        }
        try await rig.start(); try await rig.tv.advance(); try await rig.sender.advance(); try await rig.tv.advance()
        await expectPairingError(.commitmentMismatch) { try await rig.sender.advance() }
        #expect(await rig.tv.attempts == 0); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test
    func `RT23 replayed commitment fails a fresh attempt reveal`() async throws {
        let rig = try PairingRig.make()
        let recorded = Mutex<Data?>(nil)
        await rig.tvWire.setHook { frame in
            if let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .commit {
                recorded.withLock { $0 = frame }
            }
            return .pass
        }
        try await rig.start(); try await rig.tv.advance()
        // Fail the connection before SAS, keeping the TV session and its original expiry.
        try await rig.senderWire.send(PairingMessage(.ack, [Data(repeating: 0, count: 32)]).encoded())
        await expectPairingError(.unexpectedMessage) { try await rig.tv.advance() }
        await rig.sender.cancel()
        let retry = retryRig(rig)
        let replay = try #require(recorded.withLock { $0 })
        await retry.tvWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)), message.kind == .commit else { return .pass }
            return .substitute(replay)
        }
        try await retry.start(); try await retry.tv.advance(); try await retry.sender.advance(); try await retry.tv.advance()
        await expectPairingError(.commitmentMismatch) { try await retry.sender.advance() }
        #expect(await rig.tv.attempts == 0); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test
    func `RT23 attempts before SAS do not consume the session budget`() async throws {
        let rig = try PairingRig.make()
        for _ in 0 ..< 12 {
            let (tvWire, attacker) = InMemoryPairingTransport.pair()
            try await rig.tv.start(transport: tvWire)
            try await attacker.send(PairingMessage(.ack, []).encoded())
            await expectPairingError(.unexpectedMessage) { try await rig.tv.advance() }
            #expect(await rig.tv.state == .failed); #expect(await rig.tv.attempts == 0)
        }
        let retry = retryRig(rig)
        try await retry.handshake()
        #expect(await rig.tv.attempts == 1); #expect(await rig.sink.stored == 0)
        #expect(await rig.advertisement.starts == 1)
        await rig.tv.cancel(); await retry.sender.cancel()
    }

    @Test
    func `RT23 split HPKE contexts and SAS grinding cannot bypass comparison within three attempts`() async throws {
        let initial = try PairingRig.make()
        var attackers: [ActiveMITM] = []
        for attempt in 1 ... 3 {
            let rig = retryRig(initial)
            let attacker = ActiveMITM(invitation: rig.tv.invitation)
            attackers.append(attacker) // Preserve the adversary's contexts across the complete attempt budget.
            let sealed = try await attack(rig, sender: rig.sender, attacker: attacker, expectedAttempt: attempt)
            #expect(!sealed)
            #expect(await rig.sink.stored == 0)
        }
        #expect(attackers.allSatisfy { $0.contextsEstablished && $0.sealedProfiles == 0 })
        #expect(await initial.tv.state == .exhausted)
        #expect(await initial.advertisement.stops == 1)
        let (wire, peer) = InMemoryPairingTransport.pair()
        await expectPairingError(.attemptsExhausted) { try await initial.tv.start(transport: wire) }
        await peer.close()
    }

    @Test
    func `RT23 nonce commitment negative control exposes successful grinding and sealing`() async throws {
        let rig = try PairingRig.make()
        let attacker = ActiveMITM(invitation: rig.tv.invitation, lateNonceGrinding: true)
        let sender = CommitmentProbeSender()
        let sealed = try await attack(rig, sender: sender, attacker: attacker, expectedAttempt: 1)
        #expect(attacker.changedCommittedNonce)
        #expect(sealed)
        #expect(await rig.sink.stored == 1)
        // The exact security assertion used above must fail when the final nonce is not bound.
        withKnownIssue("Negative control deliberately omits the sender's final nonce commitment check") {
            #expect(!sealed)
        }
        await rig.tv.cancel()
    }

    @Test
    func `RT23 production sender rejects late nonce substitution before displaying SAS`() async throws {
        let rig = try PairingRig.make()
        let attacker = ActiveMITM(invitation: rig.tv.invitation, lateNonceGrinding: true, maximumNonceGuesses: 1)
        await rig.tvWire.setHook { attacker.fromTV($0) }
        await rig.senderWire.setHook { attacker.fromSender($0) }
        try await handshakeToFinalReveal(rig, sender: rig.sender)
        await expectPairingError(.commitmentMismatch) { try await rig.sender.advance() }
        #expect(await rig.sender.shortAuthenticationString == nil)
        #expect(attacker.changedCommittedNonce && attacker.sealedProfiles == 0)
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    private func handshakeToFinalReveal(_ rig: PairingRig, sender: any MITMSender) async throws {
        try await rig.tv.start(transport: rig.tvWire); try await sender.start(transport: rig.senderWire)
        try await rig.tv.advance(); try await sender.advance(); try await rig.tv.advance()
        try await sender.advance(); try await rig.tv.advance(); try await sender.advance()
        try await rig.tv.advance(); try await rig.tv.advance()
    }

    private func attack(_ rig: PairingRig, sender: any MITMSender, attacker: ActiveMITM, expectedAttempt: Int) async throws -> Bool {
        await rig.tvWire.setHook { attacker.fromTV($0) }
        await rig.senderWire.setHook { attacker.fromSender($0) }
        try await handshakeToFinalReveal(rig, sender: sender)
        try await sender.advance()
        #expect(await rig.tv.attempts == expectedAttempt)
        let tvSAS = try #require(await rig.tv.shortAuthenticationString)
        let senderSAS = try #require(await sender.shortAuthenticationString)
        let consent = tvSAS == senderSAS
        if consent {
            try await rig.tv.confirmSAS(tvSAS, accepted: consent)
            try await sender.advance()
            try await sender.confirmSAS(senderSAS, accepted: consent)
            try await rig.tv.advance()
            try await sender.sendProfile(PairingFixtures.profile())
            try await rig.tv.advance()
        } else {
            await expectPairingError(.rejected) { try await rig.tv.confirmSAS(tvSAS, accepted: consent) }
        }
        let sealed = attacker.sealedProfiles > 0
        await sender.cancel()
        return sealed
    }

    @Test(arguments: [true, false])
    func `RT23 transcript alteration and forged confirmation fail before sealing`(alterTranscript: Bool) async throws {
        let rig = try PairingRig.make(manual: false)
        let reveals = Mutex(0)
        await rig.tvWire.setHook { frame in
            guard let message = try? PairingMessage.decode(PairingFrame.decode(frame)) else { return .pass }
            var fields = message.fields
            if alterTranscript, message.kind == .reveal {
                let first = reveals.withLock { $0 += 1; return $0 == 1 }
                if first {
                    fields[2][0] ^= 1
                }
            } else if !alterTranscript, message.kind == .sasConfirm {
                fields[1][0] ^= 1
            } else {
                return .pass
            }
            guard let replacement = try? PairingFrame.encode(PairingMessage(message.kind, fields).encoded()) else { return .pass }
            return .substitute(replacement)
        }
        try await rig.handshake(expectMatching: false)
        let sas = try #require(await rig.tv.shortAuthenticationString)
        try await rig.tv.confirmSAS(sas, accepted: true)
        await expectPairingError(.authenticationFailed) { try await rig.sender.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test(arguments: [true, false])
    func `RT23 truncated and oversized wire frames hard close without storing`(oversize: Bool) async throws {
        let rig = try PairingRig.make()
        await rig.senderWire.setHook { frame in
            .substitute(oversize ? Data([0, 1, 0, 1]) : Data(frame.dropLast()))
        }
        try await rig.start()
        await expectPairingError(oversize ? .frameOverflow : .truncatedFrame) { try await rig.tv.advance() }
        #expect(await rig.tv.attempts == 0); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `RT23 reordered handshake messages fail the state machine`() async throws {
        let rig = try PairingRig.make()
        await rig.senderWire.setHook { _ in .reorder }
        try await rig.start() // hello is held by the attacker.
        try await rig.senderWire.send(PairingMessage(.ack, []).encoded()) // ack arrives before hello.
        await expectPairingError(.unexpectedMessage) { try await rig.tv.advance() }
        #expect(await rig.sink.stored == 0); #expect(await rig.tv.attempts == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    private func retryRig(_ rig: PairingRig) -> PairingRig {
        let (tvWire, senderWire) = InMemoryPairingTransport.pair()
        return PairingRig(
            tv: rig.tv,
            sender: PairingSender(clock: rig.clock),
            tvWire: tvWire,
            senderWire: senderWire,
            sink: rig.sink,
            advertisement: rig.advertisement,
            clock: rig.clock,
            manual: true,
        )
    }
}
