// SPDX-License-Identifier: MIT
import CryptoKit
import Foundation
import WGEXCore

/// TV receiver. Drive one `advance()` per inbound message; confirmations are explicit UI actions.
public actor PairingSession {
    public enum State: String, Sendable, CaseIterable {
        case idle, awaitingHello, awaitingCommitAck, awaitingContext, awaitingSASCommit, awaitingSASReveal, awaitingConfirmation
        case awaitingSenderConfirmation, awaitingProfile, reviewing, storing, completed, failed, cancelled, expired, exhausted
    }

    public private(set) var state: State = .idle
    public private(set) var attempts = 0
    public private(set) var shortAuthenticationString: String?
    public nonisolated let invitation: PairingInvitation
    public nonisolated let deadline: Duration
    private var privateKey: Curve25519.KeyAgreement.PrivateKey?
    private let clock: any PairingClock
    private let advertiser: any PairingAdvertising
    private let sink: any PairingProfileSink
    private var transport: any PairingTransport?
    private var expiryTask: Task<Void, Never>?
    private var advertising = false
    private var busy = false
    private var mode: PairingMode = .manual
    private var nonce = Data()
    private var senderKey = Data()
    private var sasNonce = Data()
    private var sasCommitment = Data()
    private var transcript = PairingTranscript()
    private var recipient: HPKE.Recipient?
    private var precedingDigest = Data()
    private var proofKey: SymmetricKey?

    public init(
        sink: any PairingProfileSink, clock: any PairingClock = ContinuousPairingClock(),
        advertiser: any PairingAdvertising = NoPairingAdvertisement(),
    ) throws {
        let key = Curve25519.KeyAgreement.PrivateKey()
        privateKey = key
        invitation = try PairingInvitation(sessionID: UUID().uuidString.lowercased(), publicKey: key.publicKey.rawRepresentation)
        self.sink = sink; self.clock = clock; self.advertiser = advertiser
        deadline = clock.now + .seconds(120)
    }

    deinit { expiryTask?.cancel() }

    /// A failed connection can retry within the original lifetime and attempt budget.
    public func start(transport: any PairingTransport) async throws {
        try await checkLive()
        guard !busy, state == .idle || state == .failed else { throw PairingError.invalidTransition }
        guard attempts < 3 else { throw PairingError.attemptsExhausted }
        busy = true; defer { busy = false }
        self.transport = transport; transcript = PairingTranscript(); recipient = nil; proofKey = nil
        shortAuthenticationString = nil
        nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        state = .awaitingHello
        do { try await activate() } catch { try await fail(error) }
    }

    /// Call when presenting the receiver UI, before accepting the first TCP connection.
    public func advertise() async throws {
        try await checkLive()
        guard !busy, state == .idle, !advertising else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do { try await activate() } catch { try await fail(error) }
    }

    private func activate() async throws {
        if expiryTask == nil {
            let clock = clock; let deadline = deadline
            expiryTask = Task { [weak self] in
                do { try await clock.sleep(until: deadline); await self?.expire() } catch {}
            }
        }
        if !advertising {
            try await advertiser.start()
            if state == .cancelled || state == .expired {
                await advertiser.stop(); try await checkLive()
            }
            advertising = true
        }
        try await checkLive()
    }

    public func advance() async throws {
        try await checkLive()
        guard !busy, [
            .awaitingHello,
            .awaitingCommitAck,
            .awaitingContext,
            .awaitingSASCommit,
            .awaitingSASReveal,
            .awaitingSenderConfirmation,
            .awaitingProfile,
        ].contains(state)
        else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do {
            let message = try await receive()
            switch state {
            case .awaitingHello: try await hello(message)
            case .awaitingCommitAck: try await commitmentAck(message)
            case .awaitingContext: try await context(message)
            case .awaitingSASCommit: try receiveSASCommit(message)
            case .awaitingSASReveal: try await finishSAS(message)
            case .awaitingSenderConfirmation: try senderConfirmation(message)
            case .awaitingProfile: try await accept(message)
            default: throw PairingError.invalidTransition
            }
        } catch { try await fail(error) }
    }

    /// Both the value comparison and acceptance must come from the user's visible SAS review.
    public func confirmSAS(_ displayedSAS: String, accepted: Bool) async throws {
        try await checkLive()
        guard !busy, state == .awaitingConfirmation, let proofKey else { throw PairingError.invalidTransition }
        busy = true; defer { busy = false }
        do {
            guard displayedSAS == shortAuthenticationString else { throw PairingError.sasMismatch }
            guard accepted else { throw PairingError.rejected }
            try await send(PairingMessage(
                .sasConfirm,
                [Data([1]), PairingCrypto.proof(proofKey, role: "tv", transcript: transcript.digest)],
            ))
            state = .awaitingSenderConfirmation
        } catch { try await fail(error) }
    }

    public func cancel() async {
        guard state != .completed, state != .expired else { return }
        await terminate(.cancelled)
    }

    /// Public for hosts that resume from suspension; the autonomous timer uses the same path.
    public func checkExpiry() async throws {
        try await checkLive()
    }
}

private extension PairingSession {
    private func commitmentAck(_ message: PairingMessage) async throws {
        guard message.kind == .ack, message.fields.isEmpty else { throw PairingError.unexpectedMessage }
        try await reveal(); state = .awaitingContext
    }

    private func senderConfirmation(_ message: PairingMessage) throws {
        guard message.kind == .sasConfirm, let proofKey else { throw PairingError.unexpectedMessage }
        try PairingCrypto.verify(message.fields[1], key: proofKey, role: "sender", transcript: precedingDigest)
        state = .awaitingProfile
    }

    private func hello(_ message: PairingMessage) async throws {
        guard message.kind == .hello, let byte = message.fields[0].first, let mode = PairingMode(rawValue: byte)
        else { throw PairingError.unexpectedMessage }
        if mode == .qr, message.fields[1] != Data(invitation.sessionID.utf8) {
            throw PairingError.invalidSessionID
        }
        self.mode = mode; senderKey = message.fields[2]
        if mode == .manual {
            let commitment = Data(SHA256.hash(data: invitation.publicKey + nonce))
            try await send(PairingMessage(.commit, [Data(invitation.sessionID.utf8), commitment]))
            state = .awaitingCommitAck
        } else {
            try await reveal(); state = .awaitingContext
        }
    }

    private func reveal() async throws {
        try await send(PairingMessage(.reveal, [Data(invitation.sessionID.utf8), invitation.publicKey, nonce]))
    }

    private func context(_ message: PairingMessage) async throws {
        guard message.kind == .ack, message.fields.count == 1, let privateKey else { throw PairingError.unexpectedMessage }
        recipient = try HPKE.Recipient(
            privateKey: privateKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
            info: PairingCrypto.info(sid: invitation.sessionID, tv: invitation.publicKey, sender: senderKey),
            encapsulatedKey: message.fields[0],
        )
        sasNonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let commitment = PairingCrypto.nonceCommitment(sid: invitation.sessionID, key: invitation.publicKey, nonce: sasNonce, role: "tv")
        try await send(PairingMessage(.commit, [Data(invitation.sessionID.utf8), commitment]))
        state = .awaitingSASCommit
    }

    private func receiveSASCommit(_ message: PairingMessage) throws {
        guard message.kind == .commit else { throw PairingError.unexpectedMessage }
        guard message.fields[0] == Data(invitation.sessionID.utf8) else { throw PairingError.invalidSessionID }
        sasCommitment = message.fields[1]
        state = .awaitingSASReveal
    }

    private func finishSAS(_ message: PairingMessage) async throws {
        guard message.kind == .reveal, let recipient, let transport else { throw PairingError.unexpectedMessage }
        guard message.fields[0] == Data(invitation.sessionID.utf8),
              message.fields[1] == senderKey else { throw PairingError.authenticationFailed }
        let commitment = PairingCrypto.nonceCommitment(sid: invitation.sessionID, key: senderKey, nonce: message.fields[2], role: "sender")
        guard commitment == sasCommitment else { throw PairingError.commitmentMismatch }
        let reveal = try PairingMessage(.reveal, [Data(invitation.sessionID.utf8), invitation.publicKey, sasNonce])
        // Reserve the SAS attempt before the final nonce can leave the TV. Dropping this reveal cannot evade the budget.
        try transcript.append(reveal)
        shortAuthenticationString = try PairingCrypto.sas(recipient.exportSecret(
            context: PairingCrypto.sasContext(transcript.digest),
            outputByteCount: 8,
        ))
        proofKey = try recipient.exportSecret(context: Data("wgex-confirm v1".utf8), outputByteCount: 32)
        attempts += 1
        state = .awaitingConfirmation
        try await transport.send(reveal.encoded()); try await checkLive()
        sasNonce.resetBytes(in: 0 ..< sasNonce.count)
    }

    private func accept(_ message: PairingMessage) async throws {
        guard message.kind == .sealedProfile, var context = recipient, let proofKey else { throw PairingError.unexpectedMessage }
        var plaintext: Data
        do { plaintext = try context.open(message.fields[0], authenticating: Data(invitation.sessionID.utf8)) }
        catch { throw PairingError.authenticationFailed }
        recipient = context
        let secret = try SecretBytes(wiping: &plaintext)
        guard secret.count <= PairingFrame.maximumProfileLength else { throw PairingError.frameOverflow }
        // WGEXCore currently exposes only array parser input; its inout overload wipes this bounded transient copy.
        var bytes = secret.withUnsafeBytes { Array($0) }
        let configuration = try validatedProfile(&bytes)
        state = .reviewing
        let exists = try await sink.contains(publicKey: configuration.profile.interface.publicKey)
        try await checkLive()
        if exists {
            let accepted = await sink.confirmOverwrite(configuration.profile)
            try await checkLive()
            guard accepted else { throw PairingError.overwriteRejected }
        }
        state = .storing
        // This call is the acceptance/commit boundary; storage must implement atomic persistence.
        do { try await sink.store(configuration) } catch { throw PairingError.storageFailed }
        try await checkLive()
        try await send(PairingMessage(.result, [PairingCrypto.proof(proofKey, role: "stored", transcript: transcript.digest)]))
        await terminate(.completed)
    }

    private func validatedProfile(_ bytes: inout [UInt8]) throws -> ParsedConfiguration {
        do {
            let parsed = try parseWgQuick(&bytes)
            guard !parsed.diagnostics.contains(where: { $0.severity == .error }) else { throw PairingError.invalidProfile }
            return parsed
        } catch { throw PairingError.invalidProfile }
    }

    private func send(_ message: PairingMessage) async throws {
        guard let transport else { throw PairingError.closed }
        try await transport.send(message.encoded()); try await checkLive()
        try transcript.append(message)
    }

    private func receive() async throws -> PairingMessage {
        guard let transport else { throw PairingError.closed }
        let data = try await transport.receive(); try await checkLive()
        let message = try PairingMessage.decode(data)
        precedingDigest = transcript.digest
        try transcript.append(message)
        return message
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
        if state == .exhausted {
            throw PairingError.attemptsExhausted
        }
        if Task.isCancelled {
            await terminate(.cancelled); throw PairingError.cancelled
        }
    }

    private func expire() async {
        guard state != .completed else { return }
        await terminate(.expired)
    }

    private func terminate(_ terminal: State) async {
        state = terminal; recipient = nil; proofKey = nil; privateKey = nil
        expiryTask?.cancel()
        await transport?.close()
        if advertising {
            advertising = false; await advertiser.stop()
        }
    }

    private func fail(_ error: any Error) async throws -> Never {
        if Task.isCancelled {
            await terminate(.cancelled); throw PairingError.cancelled
        }
        let mapped = error as? PairingError ?? .authenticationFailed
        if state != .expired, state != .cancelled {
            state = attempts >= 3 ? .exhausted : .failed
            recipient = nil; proofKey = nil
            await transport?.close()
            if state == .exhausted {
                await terminate(.exhausted)
            }
        }
        if state == .cancelled {
            throw PairingError.cancelled
        }
        throw state == .expired ? PairingError.expired : mapped
    }
}
