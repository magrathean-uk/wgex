// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonClient
import WGEXDaemonProtocol

package actor ClientService: DaemonService {
    package let id = UUID(uuidString: "11111111-1111-1111-1111-111111111111") ?? UUID()
    package init() {}

    package var requests: [Request] = []
    private var registrations: [UUID: DaemonProfile] = [:]
    package var status = TunnelStatus.idle
    package var secretStarts = 0
    package var lastPrivateKeyMatches = false
    package var expectedSeed: Int?
    package var expectedPublicKey: PublicKey?
    package func expectPublicKey(_ key: PublicKey) {
        expectedPublicKey = key
    }

    package var active: UUID?
    package var installReport = SecureInstallReport(
        state: .verified,
        bundlePath: "/Applications/WGEX.app",
        isUnderApplications: true,
        bundleIdentity: .matched,
        daemonIdentity: .matched,
    )
    package var failFollowUp = false
    private var repairCompleted = false
    package func failRepairFollowUp() {
        failFollowUp = true
    }

    package var repairResult: SecureInstallReport?
    package func configureInstall(_ report: SecureInstallReport, repaired: SecureInstallReport? = nil) {
        installReport = report; repairResult = repaired
    }

    package func ownerUID(for profileID: UUID) -> uid_t? {
        profileID == id ? 501 : nil
    }

    package func profileIDs(ownedBy uid: uid_t) -> Set<UUID> {
        uid == 501 ? [id] : []
    }

    package func protectionOwnerUID() -> uid_t? {
        501
    }

    package func currentSettings() -> MacGlobalSettings {
        .defaults
    }

    package func activeProfileID() -> UUID? {
        active
    }

    package func expectSeed(_ seed: Int) {
        expectedSeed = seed
    }

    package func setStatus(_ next: TunnelStatus) {
        status = next
    }

    package func profileRevision(_ id: UUID, context _: DaemonRequestContext) -> Reply {
        requests.append(.profileRevision(id))
        return .profileRevision(registrations[id]?.revision)
    }

    package func installProfileCAS(_ profile: TunnelProfile, expectedRevision: UInt64?, context _: DaemonRequestContext) -> Reply {
        requests.append(.installProfileCAS(profile, expectedRevision: expectedRevision))
        let old = registrations[profile.id]
        if old?.profile == profile {
            return .profileRevision(old?.revision)
        }
        guard expectedRevision == old?.revision else { return .profileRevisionConflict(currentRevision: old?.revision) }
        let revision = (old?.revision ?? 0) + 1
        registrations[profile.id] = .init(profile: profile, revision: revision)
        return .profileRevision(revision)
    }

    private var stopStatus: TunnelStatus?
    private var stopError: DaemonError?
    package func configureStop(status: TunnelStatus, error: DaemonError?) {
        stopStatus = status; stopError = error; active = id
    }

    package func handle(_ request: Request, context _: DaemonRequestContext, secrets: consuming SecretBundle?) -> Reply {
        requests.append(request)
        switch request {
        case .secureInstallStatus:
            return secureInstallReply()
        case .performSecureInstall:
            repairCompleted = true
            installReport = repairResult ?? installReport
            return .secureInstall(installReport)
        case .status: return .status(status)
        case .statistics:
            return .statistics(TunnelStatistics(
                generation: 77,
                sampledAt: Date(timeIntervalSince1970: 0),
                interfaceName: nil,
                listenPort: nil,
                peers: [],
            ))
        case let .startIntent(id, _, _), let .startCutover(id, _, _):
            guard let secrets else { return .error(.secretsUnavailable) }
            secretStarts += 1
            if let key = try? secrets.privateKey() {
                lastPrivateKeyMatches = matches(key)
            }
            active = id
            return .started(Generation(rawValue: 77))
        case .stop: return stopReply()
        default: return .ok
        }
    }

    private func matches(_ key: consuming SecretBytes) -> Bool {
        if let expectedPublicKey {
            return (try? PrivateKey(bytes: key).publicKey()) == expectedPublicKey
        }
        return key.withUnsafeBytes { raw in
            if let expectedSeed {
                return raw.indices.allSatisfy { raw[$0] == UInt8(truncatingIfNeeded: expectedSeed * 7 + $0) }
            }
            return raw.allSatisfy { $0 == 0xA5 }
        }
    }

    private func stopReply() -> Reply {
        active = nil
        if let stopStatus {
            status = stopStatus; active = stopStatus.activeProfileID
        }
        return stopError.map(Reply.error) ?? .ok
    }

    private func secureInstallReply() -> Reply {
        if failFollowUp, repairCompleted {
            return .error(.disconnected)
        }
        return .secureInstall(installReport)
    }
}

package actor RecordingClientTransport: XPCTransport {
    package let base: InMemoryXPCTransport
    package var envelopes: [Data] = []
    package var requests: [Request] = []
    package var callbacks: XPCClientCallbacks?
    package var connectionAttempts = 0
    package var failuresRemaining = 0
    package var replyOverride: Reply?
    private var requestOverrides: [RequestKind: Reply] = [:]
    package var secretsObserved = false
    package var lostCASReply: DaemonError?

    private let wireCallbacks: Bool

    package init(_ dispatcher: DaemonDispatcher, wireCallbacks: Bool = false) {
        self.wireCallbacks = wireCallbacks
        base = InMemoryXPCTransport(
            daemon: dispatcher,
            peer: .init(uid: 501, pid: 99, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
    }

    package func connect(callbacks: XPCClientCallbacks) async throws {
        connectionAttempts += 1
        if failuresRemaining > 0 {
            failuresRemaining -= 1; throw DaemonError.disconnected
        }
        self.callbacks = callbacks
        if wireCallbacks {
            let exported = ClientEventsExport(callbacks: callbacks)
            let provide = NSXPCDaemonListener.secretsCallback(proxy: { _ in exported })
            try await base.connect(callbacks: .init(event: callbacks.event, provideSecrets: provide, invalidated: callbacks.invalidated))
        } else {
            try await base.connect(callbacks: callbacks)
        }
    }

    package func send(_ envelope: Data, secrets: Data?) async throws -> Data {
        envelopes.append(envelope)
        let request = try Envelope.decode(envelope).body
        requests.append(request)
        secretsObserved = secretsObserved || !(secrets?.isEmpty ?? true)
        if let reply = requestOverrides[request.kind] {
            return try WireCodec.encode(reply)
        }
        if let replyOverride {
            return try WireCodec.encode(replyOverride)
        }
        let reply = try await base.send(envelope, secrets: secrets)
        if case .installProfileCAS = try Envelope.decode(envelope).body, let failure = lostCASReply {
            lostCASReply = nil
            throw failure
        }
        return reply
    }

    package func invalidate() async {
        await base.invalidate()
    }

    package func failConnections(_ count: Int) {
        failuresRemaining = count
    }

    package func override(_ reply: Reply?) {
        replyOverride = reply
    }

    package func loseNextCASReply(_ error: DaemonError) {
        lostCASReply = error
    }

    package func override(_ reply: Reply, for kind: RequestKind) {
        requestOverrides[kind] = reply
    }

    package func interrupt() async {
        await base.simulateInterruption()
    }

    package func askForSecrets(_ id: UUID) async throws -> Data {
        guard let callbacks else { throw DaemonError.disconnected }
        return try await callbacks.provideSecrets(id)
    }
}

package final class AdvancingClock: Sendable {
    private struct State { var now: TimeInterval = 0; var delays: [Duration] = [] }
    private let state = Mutex(State())
    package var elapsed: TimeInterval {
        state.withLock { $0.now }
    }

    package var delays: [Duration] {
        state.withLock { $0.delays }
    }

    package var clock: XPCClock {
        XPCClock(now: { self.elapsed }, sleep: { duration in
            self.state.withLock {
                $0.delays.append(duration)
                let parts = duration.components
                $0.now += Double(parts.seconds) + Double(parts.attoseconds) / 1e18
            }
            try Task.checkCancellation()
        })
    }
}

package func clientFixture(clock: XPCClock = .continuous) -> (ClientService, DaemonDispatcher, RecordingClientTransport, DaemonClient) {
    let service = ClientService()
    let dispatcher = DaemonDispatcher(
        service: service, daemonVersion: "1.0", daemonBuild: 10, minimumClientBuild: 5,
        authorisation: .init(isConsoleUser: { _ in true }), clock: clock,
    )
    let transport = RecordingClientTransport(dispatcher)
    let client = DaemonClient(transport: transport, clientVersion: "1.0", clientBuild: 10, clock: clock, jitter: { 1 })
    return (service, dispatcher, transport, client)
}
