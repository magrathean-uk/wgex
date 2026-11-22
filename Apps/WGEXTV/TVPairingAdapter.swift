// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXPairing
import WGEXUI

/// Public WGEXPairing adapter. No transport is opened until the pairing screen starts it on a device.
@MainActor
internal final class TVPairingAdapter: TVPairingReceiving, PairingProfileSink {
    private let app: TVAppModel
    private var session: PairingSession?
    private var overwrite: CheckedContinuation<Bool, Never>?
    private var pump: Task<Void, Never>?
    private var revision = 0

    internal init(app: TVAppModel) {
        self.app = app
    }

    internal func start() async throws -> TVPairingSnapshot {
        await stop()
        let advertiser = BonjourAdvertiser(name: "WGEX Apple TV") { [weak self] transport in
            await self?.receive(transport)
        }
        let session = try PairingSession(sink: self, advertiser: advertiser)
        self.session = session
        try await session.advertise()
        return await snapshot()
    }

    private func receive(_ transport: NWPairingTransport) async {
        guard pump == nil, let session else { await transport.close(); return }
        let current = revision
        pump = Task {
            defer {
                if current == revision {
                    pump = nil
                }
            }
            do {
                try await session.start(transport: transport)
                while !Task.isCancelled {
                    switch await session.state {
                    case .awaitingConfirmation:
                        try await Task.sleep(for: .milliseconds(100))
                    case .awaitingHello, .awaitingCommitAck, .awaitingContext, .awaitingSASCommit,
                         .awaitingSASReveal, .awaitingSenderConfirmation, .awaitingProfile:
                        try await session.advance()
                    default: return
                    }
                }
            } catch { await transport.close() }
        }
    }

    internal func snapshot() async -> TVPairingSnapshot {
        guard let session else { return TVPairingSnapshot(stage: .stopped) }
        let stage: TVPairingSnapshot.Stage = if overwrite != nil {
            .overwrite
        } else {
            switch await session.state {
            case .awaitingConfirmation: .confirmSAS
            case .awaitingSenderConfirmation, .awaitingProfile, .reviewing, .storing: .receiving
            case .completed: .completed
            case .failed: .failed
            case .expired: .expired
            case .exhausted: .exhausted
            case .cancelled: .stopped
            default: .waiting
            }
        }
        return await TVPairingSnapshot(
            payload: PairingQRCodec.encode(session.invitation),
            stage: stage,
            sas: session.shortAuthenticationString,
            attempts: session.attempts,
        )
    }

    internal func confirmSAS(_ sas: String, accepted: Bool) async throws {
        try await session?.confirmSAS(sas, accepted: accepted)
    }

    internal func confirmOverwrite(_ accepted: Bool) async {
        overwrite?.resume(returning: accepted); overwrite = nil
    }

    internal func stop() async {
        revision += 1
        pump?.cancel(); pump = nil
        overwrite?.resume(returning: false); overwrite = nil
        let previous = session; session = nil
        await previous?.cancel()
    }

    @MainActor internal func contains(publicKey: PublicKey) async throws -> Bool {
        app.profiles.contains { $0.interface.publicKey == publicKey }
    }

    @MainActor internal func confirmOverwrite(_ profile: TunnelProfile) async -> Bool {
        await withCheckedContinuation { overwrite = $0 }
    }

    @MainActor internal func store(_ configuration: consuming ParsedConfiguration) async throws {
        try await app.acceptPairing(configuration)
    }
}
