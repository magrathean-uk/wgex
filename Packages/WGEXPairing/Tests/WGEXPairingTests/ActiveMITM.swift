// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import Synchronization
@testable import WGEXPairing

/// Full active relay, retaining both contexts to translate confirmations and decrypt/reseal a profile if consent is obtained.
/// Honest peers bind the final nonces before revealing them. The negative control permits a late nonce grind on one leg.
package final class ActiveMITM: Sendable {
    private struct State {
        var senderKey = Data()
        var tvTranscript = PairingTranscript()
        var senderTranscript = PairingTranscript()
        var senderHash = SHA256()
        var recipient: HPKE.Recipient?
        var sender: HPKE.Sender?
        var tvCommits = 0
        var tvReveals = 0
        var sealed = 0
        var changedNonce = false
    }

    private let key = Curve25519.KeyAgreement.PrivateKey()
    private let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    private let invitation: PairingInvitation
    private let lateNonceGrinding: Bool
    private let maximumNonceGuesses: Int
    private let storage = Mutex(State())

    package init(invitation: PairingInvitation, lateNonceGrinding: Bool = false, maximumNonceGuesses: Int = 32_000_000) {
        self.invitation = invitation; self.lateNonceGrinding = lateNonceGrinding
        self.maximumNonceGuesses = maximumNonceGuesses
    }

    package var contextsEstablished: Bool {
        storage.withLock { $0.recipient != nil && $0.sender != nil }
    }

    package var sealedProfiles: Int {
        storage.withLock { $0.sealed }
    }

    package var changedCommittedNonce: Bool {
        storage.withLock { $0.changedNonce }
    }

    package func fromTV(_ frame: Data) -> InMemoryPairingTransport.Fault {
        do {
            let message = try PairingMessage.decode(PairingFrame.decode(frame))
            let replacement = try storage.withLock { state -> PairingMessage in
                var replacement = message
                if message.kind == .commit {
                    state.tvCommits += 1
                    let digest = state.tvCommits == 1 ? Data(SHA256.hash(data: key.publicKey.rawRepresentation + nonce)) :
                        PairingCrypto.nonceCommitment(
                            sid: invitation.sessionID,
                            key: key.publicKey.rawRepresentation,
                            nonce: nonce,
                            role: "tv",
                        )
                    replacement = try PairingMessage(.commit, [message.fields[0], digest])
                } else if message.kind == .reveal {
                    state.tvReveals += 1
                    replacement = try PairingMessage(.reveal, [message.fields[0], key.publicKey.rawRepresentation, nonce])
                    if state.tvReveals == 2, lateNonceGrinding {
                        var tvFinal = state.tvTranscript; try tvFinal.append(message)
                        replacement = try grindFinalNonce(state: state, tvFinal: tvFinal)
                        state.changedNonce = replacement.fields[2] != nonce
                    }
                } else if message.kind == .sasConfirm, let recipient = state.recipient {
                    let proofKey = try recipient.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
                    replacement = try PairingMessage(.sasConfirm, [
                        Data([1]), PairingCrypto.proof(proofKey, role: "tv", transcript: state.senderTranscript.digest),
                    ])
                } else if message.kind == .result, let recipient = state.recipient {
                    let proofKey = try recipient.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
                    replacement = try PairingMessage(
                        .result,
                        [PairingCrypto.proof(proofKey, role: "stored", transcript: state.senderTranscript.digest)],
                    )
                }
                try state.tvTranscript.append(message); try state.senderTranscript.append(replacement)
                try state.senderHash.update(data: PairingFrame.encode(replacement.encoded()))
                return replacement
            }
            return try .substitute(PairingFrame.encode(replacement.encoded()))
        } catch { return .substitute(Data()) }
    }

    package func fromSender(_ frame: Data) -> InMemoryPairingTransport.Fault {
        do {
            let message = try PairingMessage.decode(PairingFrame.decode(frame))
            let replacement = try storage.withLock { state -> PairingMessage in
                var replacement = message
                if message.kind == .hello {
                    state.senderKey = message.fields[2]
                }
                if message.kind == .ack, message.fields.count == 1 {
                    let recipient = try HPKE.Recipient(
                        privateKey: key, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                        info: PairingCrypto.info(sid: invitation.sessionID, tv: key.publicKey.rawRepresentation, sender: state.senderKey),
                        encapsulatedKey: message.fields[0],
                    )
                    state.recipient = recipient
                    var senderTranscript = state.senderTranscript; try senderTranscript.append(message)
                    let target = try PairingCrypto.sas(recipient.exportSecret(
                        context: PairingCrypto.sasContext(senderTranscript.digest), outputByteCount: 8,
                    ))
                    replacement = try grindEncapsulation(target: target, state: &state)
                } else if message.kind == .sasConfirm, let sender = state.sender {
                    let proofKey = try sender.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
                    replacement = try PairingMessage(.sasConfirm, [
                        Data([1]), PairingCrypto.proof(proofKey, role: "sender", transcript: state.tvTranscript.digest),
                    ])
                } else if message.kind == .sealedProfile, var recipient = state.recipient, var sender = state.sender {
                    var plaintext = try recipient.open(message.fields[0], authenticating: Data(invitation.sessionID.utf8))
                    defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
                    let sealed = try sender.seal(plaintext, authenticating: Data(invitation.sessionID.utf8))
                    state.recipient = recipient; state.sender = sender; state.sealed += 1
                    replacement = try PairingMessage(.sealedProfile, [sealed])
                }
                try state.senderTranscript.append(message); try state.tvTranscript.append(replacement)
                try state.senderHash.update(data: PairingFrame.encode(message.encoded()))
                return replacement
            }
            return try .substitute(PairingFrame.encode(replacement.encoded()))
        } catch { return .substitute(Data()) }
    }

    private func grindEncapsulation(target: String, state: inout State) throws -> PairingMessage {
        var chosen = try PairingMessage(.ack, [Data(repeating: 0, count: 32)])
        for _ in 0 ..< 64 {
            let context = try HPKE.Sender(
                recipientKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: invitation.publicKey),
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: PairingCrypto.info(sid: invitation.sessionID, tv: invitation.publicKey, sender: state.senderKey),
            )
            chosen = try PairingMessage(.ack, [context.encapsulatedKey])
            state.sender = context
            var transcript = state.tvTranscript; try transcript.append(chosen)
            let sas = try PairingCrypto.sas(context.exportSecret(context: PairingCrypto.sasContext(transcript.digest), outputByteCount: 8))
            if sas == target {
                break
            }
        }
        return chosen
    }

    private func grindFinalNonce(state: State, tvFinal: PairingTranscript) throws -> PairingMessage {
        guard let sender = state.sender, let recipient = state.recipient else { throw PairingError.invalidTransition }
        let target = try PairingCrypto.sas(sender.exportSecret(context: PairingCrypto.sasContext(tvFinal.digest), outputByteCount: 8))
        // Hash the exact canonical frame, varying only the nonce; avoid repeated UUID parsing and message validation.
        let targetValue = UInt64(target)
        let empty = try PairingMessage(.reveal, [Data(invitation.sessionID.utf8), key.publicKey.rawRepresentation, Data(count: 32)])
        var frame = try PairingFrame.encode(empty.encoded())
        let nonceOffset = frame.count - 32
        for number in 0 ..< maximumNonceGuesses {
            withUnsafeBytes(of: UInt64(number).bigEndian) { frame.replaceSubrange(nonceOffset ..< nonceOffset + 8, with: $0) }
            var hash = state.senderHash; hash.update(data: frame)
            let exported = try recipient.exportSecret(context: PairingCrypto.sasContext(Data(hash.finalize())), outputByteCount: 8)
            if Self.sasPrefix(exported) == targetValue {
                print("WGEX negative-control nonce guesses: \(number + 1)")
                return try PairingMessage.decode(PairingFrame.decode(frame))
            }
        }
        // A failed grind still submits its last guess. Honest commitment verification must reject it.
        return try PairingMessage.decode(PairingFrame.decode(frame))
    }

    private static func sasPrefix(_ key: SymmetricKey) -> UInt64 {
        var value = key.withUnsafeBytes { $0.reduce(UInt64(0)) { $0 << 8 | UInt64($1) } }
        while value >= 1_000_000 {
            value /= 10
        }
        return value
    }
}
