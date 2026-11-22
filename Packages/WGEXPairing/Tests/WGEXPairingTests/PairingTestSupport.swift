// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXPairing

private struct ClockState {
    var now: Duration = .zero
    var waiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
    var cancelled: Set<UUID> = []
}

package final class TestPairingClock: PairingClock, Sendable {
    private let storage = Mutex(ClockState())
    package var now: Duration {
        storage.withLock { $0.now }
    }

    package func advance(by duration: Duration) {
        let pending = storage.withLock { state in
            state.now += duration
            let pending = Array(state.waiters.values)
            state.waiters.removeAll()
            return pending
        }
        for waiter in pending {
            waiter.resume()
        }
    }

    package func sleep(until deadline: Duration) async throws {
        while now < deadline {
            let id = UUID()
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    // Decided under the lock, resumed outside it, as HostClock does (consistency). The deadlock this rule
                    // prevents is on the advance path, which resumes a task that is already awaiting: that resume needs the
                    // task's status-record lock, a cancel holds it while its handler wants this lock. Here the continuation is
                    // resumed before its task awaits it, which needs no such lock; the rule is kept, not required, on this
                    // path (M1-31 VERIFY INFO 3).
                    let outcome = storage.withLock { state -> Result<Void, CancellationError>? in
                        if state.cancelled.remove(id) != nil || Task.isCancelled {
                            return .failure(CancellationError())
                        } else if state.now >= deadline {
                            return .success(())
                        }
                        state.waiters[id] = continuation
                        return nil
                    }
                    switch outcome {
                    case .failure: continuation.resume(throwing: CancellationError())
                    case .success: continuation.resume()
                    case nil: break
                    }
                }
            } onCancel: {
                let pending = self.storage.withLock { state in
                    let pending = state.waiters.removeValue(forKey: id)
                    if pending == nil {
                        state.cancelled.insert(id)
                    }
                    return pending
                }
                pending?.resume(throwing: CancellationError())
            }
        }
    }
}

package actor TestAdvertisement: PairingAdvertising {
    package private(set) var starts = 0
    package private(set) var stops = 0
    package func start() {
        starts += 1
    }

    package func stop() {
        stops += 1
    }
}

package actor TestProfileSink: PairingProfileSink {
    package private(set) var stored = 0
    package private(set) var overwriteRequests = 0
    package private(set) var storedKey: PublicKey?
    package var exists = false
    package var allowOverwrite = false
    package var failStorage = false
    package var reviewHook: (@Sendable () async -> Void)?
    package var storeHook: (@Sendable () async -> Void)?

    package func configure(exists: Bool = false, allowOverwrite: Bool = false, failStorage: Bool = false) {
        self.exists = exists; self.allowOverwrite = allowOverwrite; self.failStorage = failStorage
    }

    package func setHooks(review: (@Sendable () async -> Void)? = nil, store: (@Sendable () async -> Void)? = nil) {
        reviewHook = review; storeHook = store
    }

    package func contains(publicKey _: PublicKey) async -> Bool {
        await reviewHook?(); return exists
    }

    package func confirmOverwrite(_: TunnelProfile) -> Bool {
        overwriteRequests += 1; return allowOverwrite
    }

    package func store(_ configuration: consuming ParsedConfiguration) async throws {
        await storeHook?()
        if failStorage {
            throw PairingError.storageFailed
        }
        stored += 1; storedKey = configuration.profile.interface.publicKey
        // Exercise the noncopyable secret hand-off without printing or persisting it.
        try configuration.secrets.withKey(configuration.profile.secrets.privateKey) { bytes in
            #expect(bytes.count == 32)
        }
    }
}

package enum PairingFixtures {
    package static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Tests/Fixtures")

    package static func profile(_ name: String = "ipv6-dual-stack.conf") throws -> ParsedConfiguration {
        var bytes = try Array(Data(contentsOf: root.appendingPathComponent("conf/\(name)")))
        return try parseWgQuick(&bytes)
    }
}

package struct PairingRig: Sendable {
    package let tv: PairingSession
    package let sender: PairingSender
    package let tvWire: InMemoryPairingTransport
    package let senderWire: InMemoryPairingTransport
    package let sink: TestProfileSink
    package let advertisement: TestAdvertisement
    package let clock: TestPairingClock
    package let manual: Bool

    package static func make(manual: Bool = true) throws -> Self {
        let sink = TestProfileSink(); let advertisement = TestAdvertisement(); let clock = TestPairingClock()
        let tv = try PairingSession(sink: sink, clock: clock, advertiser: advertisement)
        let sender = PairingSender(invitation: manual ? nil : tv.invitation, clock: clock)
        let (tvWire, senderWire) = InMemoryPairingTransport.pair()
        return Self(
            tv: tv,
            sender: sender,
            tvWire: tvWire,
            senderWire: senderWire,
            sink: sink,
            advertisement: advertisement,
            clock: clock,
            manual: manual,
        )
    }

    package func start() async throws {
        try await tv.start(transport: tvWire); try await sender.start(transport: senderWire)
    }

    package func handshake(expectMatching: Bool = true, expectedAttempt: Int = 1) async throws {
        try await start()
        try await tv.advance()
        if manual {
            #expect(await tv.state == .awaitingCommitAck)
            try await sender.advance(); #expect(await sender.state == .awaitingReveal)
            try await tv.advance()
        }
        #expect(await tv.state == .awaitingContext)
        try await sender.advance(); #expect(await sender.state == .awaitingSASCommit)
        try await tv.advance(); #expect(await tv.state == .awaitingSASCommit)
        try await sender.advance(); #expect(await sender.state == .awaitingSASReveal)
        try await tv.advance(); #expect(await tv.state == .awaitingSASReveal)
        try await tv.advance(); #expect(await tv.state == .awaitingConfirmation)
        try await sender.advance(); #expect(await sender.state == .awaitingTVConfirmation)
        let sas = try #require(await tv.shortAuthenticationString)
        #expect(sas.count == 6 && sas.utf8.allSatisfy { (48 ... 57).contains($0) })
        if expectMatching {
            #expect(await sender.shortAuthenticationString == sas)
        }
        #expect(await tv.attempts == expectedAttempt)
    }

    package func confirm() async throws {
        let sas = try #require(await tv.shortAuthenticationString)
        try await tv.confirmSAS(sas, accepted: true)
        #expect(await tv.state == .awaitingSenderConfirmation)
        try await sender.advance()
        if manual {
            #expect(await sender.state == .awaitingLocalConfirmation)
            try await sender.confirmSAS(sas, accepted: true)
        }
        #expect(await sender.state == .readyToSeal)
        try await tv.advance(); #expect(await tv.state == .awaitingProfile)
    }
}

package func expectPairingError(_ expected: PairingError, _ operation: () async throws -> Void) async {
    do { try await operation(); Issue.record("Expected typed pairing error") }
    catch let error as PairingError { #expect(error == expected) }
    catch { Issue.record("Unexpected error type") }
}
