// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import WGEXCore
@testable import WGEXPairing

/// Common driver interface lets the same adversary and consent oracle exercise the real sender and the negative control.
package protocol MITMSender: Actor {
    var shortAuthenticationString: String? { get }
    func start(transport: any PairingTransport) async throws
    func advance() async throws
    func confirmSAS(_ displayedSAS: String, accepted: Bool) async throws
    func sendProfile(_ configuration: consuming ParsedConfiguration) async throws
    func cancel() async
}

extension PairingSender: MITMSender {}

/// Test-only manual sender modelling the frozen sender's commitment, transcript, exporter, proof and sealing steps.
/// Its single intentional weakness is skipping the final TV nonce commitment check. No production hook is installed.
package actor CommitmentProbeSender: MITMSender {
    package private(set) var shortAuthenticationString: String?
    private let senderKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
    private var wire: any PairingTransport?
    private var transcript = PairingTranscript()
    private var context: HPKE.Sender?
    private var proofKey: SymmetricKey?
    private var sid = ""
    private var tvKey = Data()
    private var commitment = Data()
    private var step = 0
    private var ready = false

    package func start(transport: any PairingTransport) async throws {
        wire = transport
        try await send(PairingMessage(.hello, [Data([PairingMode.manual.rawValue]), Data(), senderKey]))
    }

    package func advance() async throws {
        guard let wire else { throw PairingError.invalidTransition }
        let message = try await PairingMessage.decode(wire.receive())
        let previous = transcript.digest
        try transcript.append(message)
        switch step {
        case 0: try await receiveInitialCommit(message)
        case 1:
            guard message.kind == .reveal,
                  Data(SHA256.hash(data: message.fields[1] + message.fields[2])) == commitment
            else {
                throw PairingError.commitmentMismatch
            }
            tvKey = message.fields[1]
            let context = try HPKE.Sender(
                recipientKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: tvKey),
                ciphersuite: .Curve25519_SHA256_ChachaPoly,
                info: PairingCrypto.info(sid: sid, tv: tvKey, sender: senderKey),
            )
            self.context = context
            try await send(PairingMessage(.ack, [context.encapsulatedKey]))
        case 2:
            guard message.kind == .commit else { throw PairingError.unexpectedMessage }
            commitment = message.fields[1]
            let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            try await send(PairingMessage(.commit, [
                Data(sid.utf8), PairingCrypto.nonceCommitment(sid: sid, key: senderKey, nonce: nonce, role: "sender"),
            ]))
            try await send(PairingMessage(.reveal, [Data(sid.utf8), senderKey, nonce]))
        case 3: try finishSAS(message)
        case 4:
            guard message.kind == .sasConfirm, let proofKey else { throw PairingError.unexpectedMessage }
            try PairingCrypto.verify(message.fields[1], key: proofKey, role: "tv", transcript: previous)
        default: throw PairingError.invalidTransition
        }
        step += 1
    }

    private func receiveInitialCommit(_ message: PairingMessage) async throws {
        guard message.kind == .commit else { throw PairingError.unexpectedMessage }
        sid = String(decoding: message.fields[0], as: UTF8.self); commitment = message.fields[1]
        try await send(PairingMessage(.ack, []))
    }

    private func finishSAS(_ message: PairingMessage) throws {
        guard message.kind == .reveal, message.fields[0] == Data(sid.utf8), message.fields[1] == tvKey,
              let context else { throw PairingError.authenticationFailed }
        // MUTATION: omit only the nonce commitment comparison performed by PairingSender.finishSAS.
        shortAuthenticationString = try PairingCrypto.sas(context.exportSecret(
            context: PairingCrypto.sasContext(transcript.digest), outputByteCount: 8,
        ))
        proofKey = try context.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
    }

    package func confirmSAS(_ displayedSAS: String, accepted: Bool) async throws {
        guard step == 5, displayedSAS == shortAuthenticationString, let proofKey else { throw PairingError.invalidTransition }
        guard accepted else { throw PairingError.rejected }
        try await send(PairingMessage(.sasConfirm, [
            Data([1]), PairingCrypto.proof(proofKey, role: "sender", transcript: transcript.digest),
        ]))
        ready = true
    }

    package func sendProfile(_ configuration: consuming ParsedConfiguration) async throws {
        guard ready, var context else { throw PairingError.invalidTransition }
        let text = try serialiseWgQuick(configuration.profile, secrets: configuration.secrets)
        var transient = text.bytes.withUnsafeBytes { Data($0) }
        defer { transient.resetBytes(in: 0 ..< transient.count) }
        let ciphertext = try context.seal(transient, authenticating: Data(sid.utf8))
        self.context = context
        try await send(PairingMessage(.sealedProfile, [ciphertext]))
    }

    package func cancel() async {
        context = nil; proofKey = nil; await wire?.close()
    }

    private func send(_ message: PairingMessage) async throws {
        guard let wire else { throw PairingError.invalidTransition }
        try await wire.send(message.encoded()); try transcript.append(message)
    }
}
