// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import WGEXCore

public actor PairingSender {
    public enum State: String, Sendable, CaseIterable {
        case idle, awaitingCommit, awaitingReveal, awaitingSASCommit, awaitingSASReveal, awaitingTVConfirmation, awaitingLocalConfirmation
        case readyToSeal, awaitingResult, completed, failed, cancelled, expired
    }

    public private(set) var state: State = .idle
    public private(set) var shortAuthenticationString: String?
    public nonisolated let deadline: Duration
    private let mode: PairingMode
    private let invitation: PairingInvitation?
    private let clock: any PairingClock
    private let senderKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
    private var transport: any PairingTransport?
    private var busy = false
    private var sessionID = ""
    private var commitment = Data()
    private var sasCommitment = Data()
    private var tvKey = Data()
    private var transcript = PairingTranscript()
    private var sender: HPKE.Sender?
    private var proofKey: SymmetricKey?
    private var expiryTask: Task<Void, Never>?

    /// Nil invitation selects manual mode; scanner-decoded invitation selects QR mode.
    public init(invitation: PairingInvitation? = nil, clock: any PairingClock = ContinuousPairingClock()) {
        self.invitation = invitation; mode = invitation == nil ? .manual : .qr
        self.clock = clock; deadline = clock.now + .seconds(120)
    }

    deinit { expiryTask?.cancel() }

    public func start(transport: any PairingTransport) async throws {
        try await checkLive()
        guard !busy, state == .idle else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        self.transport = transport
        let clock = clock; let deadline = deadline
        expiryTask = Task { [weak self] in
            do { try await clock.sleep(until: deadline); await self?.expire() } catch {}
        }
        do {
            try await send(PairingMessage(.hello, [Data([mode.rawValue]), Data((invitation?.sessionID ?? "").utf8), senderKey]))
            state = mode == .manual ? .awaitingCommit : .awaitingReveal
        } catch { try await fail(error) }
    }

    public func advance() async throws {
        try await checkLive()
        guard !busy,
              [.awaitingCommit, .awaitingReveal, .awaitingSASCommit, .awaitingSASReveal, .awaitingTVConfirmation, .awaitingResult]
                  .contains(state)
        else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do {
            guard let transport else { throw PairingError.closed }
            let message = try await PairingMessage.decode(transport.receive()); try await checkLive()
            let previous = transcript.digest
            try transcript.append(message)
            switch state {
            case .awaitingCommit: try await receiveCommit(message)
            case .awaitingReveal: try await reveal(message)
            case .awaitingSASCommit: try await commitSAS(message)
            case .awaitingSASReveal: try finishSAS(message)
            case .awaitingTVConfirmation: try await tvConfirmation(message, previous: previous)
            case .awaitingResult: try await receiveResult(message, previous: previous)
            default: throw PairingError.invalidTransition
            }
        } catch { try await fail(error) }
    }

    public func confirmSAS(_ displayedSAS: String, accepted: Bool) async throws {
        try await checkLive()
        guard !busy, state == .awaitingLocalConfirmation else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do {
            guard displayedSAS == shortAuthenticationString else { throw PairingError.sasMismatch }
            guard accepted else { throw PairingError.rejected }
            try await confirm(); state = .readyToSeal
        } catch { try await fail(error) }
    }

    public func sendProfile(_ configuration: consuming ParsedConfiguration) async throws {
        try await checkLive()
        guard !busy, state == .readyToSeal, var context = sender else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do {
            let text = try serialiseWgQuick(configuration.profile, secrets: configuration.secrets)
            guard text.byteCount <= PairingFrame.maximumProfileLength else { throw PairingError.frameOverflow }
            var transient = text.bytes.withUnsafeBytes { Data($0) }
            defer { transient.resetBytes(in: 0 ..< transient.count) }
            let ciphertext = try context.seal(transient, authenticating: Data(sessionID.utf8))
            sender = context
            try await send(PairingMessage(.sealedProfile, [ciphertext])); state = .awaitingResult
        } catch { try await fail(error) }
    }

    public func cancel() async {
        guard state != .completed, state != .expired else { return }
        await terminate(.cancelled)
    }

    public func checkExpiry() async throws {
        try await checkLive()
    }

    private func receiveCommit(_ message: PairingMessage) async throws {
        guard message.kind == .commit else { throw PairingError.unexpectedMessage }
        sessionID = String(decoding: message.fields[0], as: UTF8.self); commitment = message.fields[1]
        try await send(PairingMessage(.ack, [])); state = .awaitingReveal
    }

    private func receiveResult(_ message: PairingMessage, previous: Data) async throws {
        guard message.kind == .result, let proofKey else { throw PairingError.unexpectedMessage }
        try PairingCrypto.verify(message.fields[0], key: proofKey, role: "stored", transcript: previous)
        await terminate(.completed)
    }

    private func reveal(_ message: PairingMessage) async throws {
        guard message.kind == .reveal else { throw PairingError.unexpectedMessage }
        let sid = String(decoding: message.fields[0], as: UTF8.self)
        let tv = message.fields[1]
        if let invitation {
            guard invitation.sessionID == sid else { throw PairingError.invalidSessionID }
            guard invitation.publicKey == tv else { throw PairingError.authenticationFailed }
        } else {
            guard sid == sessionID else { throw PairingError.invalidSessionID }
            guard Data(SHA256.hash(data: tv + message.fields[2])) == commitment else { throw PairingError.commitmentMismatch }
        }
        sessionID = sid
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: tv)
        let context = try HPKE.Sender(
            recipientKey: key, ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: PairingCrypto.info(sid: sid, tv: tv, sender: senderKey),
        )
        sender = context
        try await send(PairingMessage(.ack, [context.encapsulatedKey]))
        tvKey = tv
        state = .awaitingSASCommit
    }

    private func commitSAS(_ message: PairingMessage) async throws {
        guard message.kind == .commit else { throw PairingError.unexpectedMessage }
        guard message.fields[0] == Data(sessionID.utf8) else { throw PairingError.invalidSessionID }
        sasCommitment = message.fields[1]
        let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let commitment = PairingCrypto.nonceCommitment(sid: sessionID, key: senderKey, nonce: nonce, role: "sender")
        try await send(PairingMessage(.commit, [Data(sessionID.utf8), commitment]))
        try await send(PairingMessage(.reveal, [Data(sessionID.utf8), senderKey, nonce]))
        state = .awaitingSASReveal
    }

    private func finishSAS(_ message: PairingMessage) throws {
        guard message.kind == .reveal, let sender else { throw PairingError.unexpectedMessage }
        guard message.fields[0] == Data(sessionID.utf8), message.fields[1] == tvKey else { throw PairingError.authenticationFailed }
        let commitment = PairingCrypto.nonceCommitment(sid: sessionID, key: tvKey, nonce: message.fields[2], role: "tv")
        guard commitment == sasCommitment else { throw PairingError.commitmentMismatch }
        shortAuthenticationString = try PairingCrypto.sas(sender.exportSecret(
            context: PairingCrypto.sasContext(transcript.digest),
            outputByteCount: 8,
        ))
        proofKey = try sender.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
        state = .awaitingTVConfirmation
    }

    private func tvConfirmation(_ message: PairingMessage, previous: Data) async throws {
        guard message.kind == .sasConfirm, let proofKey else { throw PairingError.unexpectedMessage }
        try PairingCrypto.verify(message.fields[1], key: proofKey, role: "tv", transcript: previous)
        if mode == .qr {
            try await confirm(); state = .readyToSeal
        } else {
            state = .awaitingLocalConfirmation
        }
    }

    private func confirm() async throws {
        guard let proofKey else { throw PairingError.invalidTransition }
        try await send(PairingMessage(
            .sasConfirm,
            [Data([1]), PairingCrypto.proof(proofKey, role: "sender", transcript: transcript.digest)],
        ))
    }

    private func send(_ message: PairingMessage) async throws {
        guard let transport else { throw PairingError.closed }
        try await transport.send(message.encoded()); try await checkLive()
        try transcript.append(message)
    }

    private func checkLive() async throws {
        if clock.now >= deadline, state != .completed {
            await expire(); throw PairingError.expired
        }
        if state == .expired {
            throw PairingError.expired
        }
        if state == .cancelled {
            throw PairingError.cancelled
        }
        if Task.isCancelled {
            await terminate(.cancelled); throw PairingError.cancelled
        }
    }

    private func expire() async {
        if state != .completed {
            await terminate(.expired)
        }
    }

    private func terminate(_ terminal: State) async {
        state = terminal; sender = nil; proofKey = nil; expiryTask?.cancel()
        await transport?.close()
    }

    private func fail(_ error: any Error) async throws -> Never {
        if Task.isCancelled {
            await terminate(.cancelled); throw PairingError.cancelled
        }
        let mapped = error as? PairingError ?? .authenticationFailed
        if state != .expired, state != .cancelled {
            await terminate(.failed)
        }
        if state == .cancelled {
            throw PairingError.cancelled
        }
        throw state == .expired ? PairingError.expired : mapped
    }
}
