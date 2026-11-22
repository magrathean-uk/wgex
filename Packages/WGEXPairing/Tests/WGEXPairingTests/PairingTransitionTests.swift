// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXPairing

private struct PairingTransitionTests {
    @Test(arguments: 0 ... 6)
    func `TV rejects an invalid message in every receive state`(stage: Int) async throws {
        let rig = try PairingRig.make()
        if stage == 0 {
            try await rig.tv.start(transport: rig.tvWire)
        } else if stage <= 4 {
            try await rig.start(); try await rig.tv.advance()
            if stage >= 2 {
                try await rig.sender.advance(); try await rig.tv.advance()
            }
            if stage >= 3 {
                try await rig.sender.advance(); try await rig.tv.advance()
            }
            if stage == 4 {
                try await rig.sender.advance(); try await rig.tv.advance()
                _ = try await rig.tvWire.receive() // Remove the genuine queued sender reveal before injecting the attack.
            }
        } else {
            try await rig.handshake()
            if stage == 5 {
                let sas = try #require(await rig.tv.shortAuthenticationString)
                try await rig.tv.confirmSAS(sas, accepted: true)
            } else {
                try await rig.confirm()
            }
        }
        let states: [PairingSession.State] = [
            .awaitingHello,
            .awaitingCommitAck,
            .awaitingContext,
            .awaitingSASCommit,
            .awaitingSASReveal,
            .awaitingSenderConfirmation,
            .awaitingProfile,
        ]
        #expect(await rig.tv.state == states[stage])
        await expectPairingError(.invalidTransition) { try await rig.tv.confirmSAS("000000", accepted: true) }
        try await rig.senderWire.send(PairingMessage(.result, [Data(repeating: 0, count: 32)]).encoded())
        await expectPairingError(.unexpectedMessage) { try await rig.tv.advance() }
        #expect(await rig.tv.state == .failed); #expect(await rig.sink.stored == 0)
        #expect(await rig.tv.attempts == (stage >= 5 ? 1 : 0))
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test(arguments: 0 ... 5)
    func `sender rejects an invalid message in every receive state`(stage: Int) async throws {
        let rig = try PairingRig.make()
        if stage <= 3 {
            try await rig.start()
            if stage >= 1 {
                try await rig.tv.advance(); try await rig.sender.advance()
            }
            if stage >= 2 {
                try await rig.tv.advance(); try await rig.sender.advance()
            }
            if stage >= 3 {
                try await rig.tv.advance(); try await rig.sender.advance()
            }
        } else {
            try await rig.handshake()
            if stage == 5 {
                try await rig.confirm(); try await rig.sender.sendProfile(PairingFixtures.profile())
            }
        }
        let states: [PairingSender.State] = [
            .awaitingCommit,
            .awaitingReveal,
            .awaitingSASCommit,
            .awaitingSASReveal,
            .awaitingTVConfirmation,
            .awaitingResult,
        ]
        #expect(await rig.sender.state == states[stage])
        await expectPairingError(.invalidTransition) { try await rig.sender.confirmSAS("000000", accepted: true) }
        try await rig.tvWire.send(PairingMessage(.ack, []).encoded())
        await expectPairingError(.unexpectedMessage) { try await rig.sender.advance() }
        #expect(await rig.sender.state == .failed); #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test
    func `sender cancellation is terminal and completed sessions remain single use`() async throws {
        let rig = try PairingRig.make()
        await rig.sender.cancel()
        #expect(await rig.sender.state == .cancelled)
        await expectPairingError(.cancelled) { try await rig.sender.start(transport: rig.senderWire) }
        await rig.tv.cancel()
    }
}
