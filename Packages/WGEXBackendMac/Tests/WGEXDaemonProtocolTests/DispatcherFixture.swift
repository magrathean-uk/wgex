// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol

package actor DispatcherService: DaemonService {
    package let profile = UUID()
    package let otherProfile = UUID()
    package var calls: [Request] = []
    package var contexts: [DaemonRequestContext] = []
    package var receivedSecrets = false
    package var active: UUID?
    package var waitForMutation = false
    private var waitedKind = RequestKind.startIntent
    package var waiting: CheckedContinuation<Void, Never>?
    package var reporterLosses = 0

    package func wifiReporterLost() {
        reporterLosses += 1
    }

    package init() {
        active = profile
    }

    package func ownerUID(for profileID: UUID) -> uid_t? {
        profileID == profile ? 501 : profileID == otherProfile ? 502 : nil
    }

    package func profileIDs(ownedBy uid: uid_t) -> Set<UUID> {
        uid == 501 ? [profile] : uid == 502 ? [otherProfile] : []
    }

    package func activeProfileID() -> UUID? {
        active
    }

    package func protectionOwnerUID() -> uid_t? {
        501
    }

    package func currentSettings() -> MacGlobalSettings {
        .defaults
    }

    package func setWaiting(for kind: RequestKind = .startIntent) {
        waitForMutation = true
        waitedKind = kind
    }

    package func release() {
        waiting?.resume(); waiting = nil
    }

    package func profileRevision(_ id: UUID, context: DaemonRequestContext) async -> Reply {
        await handle(.profileRevision(id), context: context, secrets: nil)
    }

    package func installProfileCAS(_ profile: TunnelProfile, expectedRevision: UInt64?, context: DaemonRequestContext) async -> Reply {
        await handle(.installProfileCAS(profile, expectedRevision: expectedRevision), context: context, secrets: nil)
    }

    package func handle(_ request: Request, context: DaemonRequestContext, secrets: consuming SecretBundle?) async -> Reply {
        calls.append(request)
        contexts.append(context)
        if let secrets {
            receivedSecrets = secrets.wireByteCount >= 37
        }
        if waitForMutation, request.kind == waitedKind {
            await withCheckedContinuation { waiting = $0 }
        }
        switch request {
        case .startIntent:
            return .started(Generation(rawValue: 42))
        case .status: return .status(.idle)
        case .profileRevision, .installProfileCAS: return .profileRevision(1)
        case .logs:
            return .logs([nil, profile, otherProfile].map {
                RedactedLogLine(date: Date(timeIntervalSince1970: 0), category: "test", message: "redacted", profileID: $0)
            })
        case .diagnostics:
            return .diagnostics(DiagnosticsBundle(createdAt: Date(timeIntervalSince1970: 0), archive: Data()))
        default: return .ok
        }
    }
}

package func testPeer(uid: uid_t = 501, pid: pid_t = 7, accepted: Bool = true) -> VerifiedPeerIdentity {
    VerifiedPeerIdentity(uid: uid, pid: pid, auditSessionID: 10, codeSigningVerdict: accepted ? .requirementSatisfied : .rejected)
}

package func call(_ transport: any XPCTransport, _ request: Request, secrets: Data? = nil) async throws -> Reply {
    try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: secrets))
}

package func handshaken(
    _ dispatcher: DaemonDispatcher,
    uid: uid_t = 501,
    callbacks: XPCClientCallbacks = .init(),
) async throws -> InMemoryXPCTransport {
    let transport = InMemoryXPCTransport(daemon: dispatcher, peer: testPeer(uid: uid))
    try await transport.connect(callbacks: callbacks)
    _ = try await call(transport, .hello(clientVersion: "test", clientBuild: 10))
    return transport
}

package extension Reply {
    var isMeasuredIdle: Bool {
        guard case let .status(status) = self else { return false }
        return status.phase == .idle && status.protection == .unprotected && status.sequence > 0 && status.measuredAt != nil
    }
}
