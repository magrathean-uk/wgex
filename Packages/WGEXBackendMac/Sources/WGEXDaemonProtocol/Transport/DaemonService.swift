// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore

/// Trusted scope provided by the dispatcher after authentication and authorisation.
public struct DaemonRequestContext: Sendable {
    public let peer: VerifiedPeerIdentity
    /// Includes only profiles owned by this uid. Empty means none, never all.
    public let visibleProfileIDs: Set<UUID>
    public let clientBuild: Int
    public let expectedGeneration: Generation?
    /// A Wi-Fi report's reporter standing, attached by the dispatcher after its eligibility checks; nil on every other request.
    public var wifiReporter: WiFiReporterMembership?
    /// The running app's secrets handoff for a start, cutover or arm sent without secrets; attached by the dispatcher, and
    /// nil on every other request.
    public var appSecrets: AppSecretsHandoff?

    public init(
        peer: VerifiedPeerIdentity, visibleProfileIDs: Set<UUID>, clientBuild: Int, expectedGeneration: Generation? = nil,
        wifiReporter: WiFiReporterMembership? = nil, appSecrets: AppSecretsHandoff? = nil,
    ) {
        self.peer = peer
        self.visibleProfileIDs = visibleProfileIDs
        self.clientBuild = clientBuild
        self.expectedGeneration = expectedGeneration
        self.wifiReporter = wifiReporter
        self.appSecrets = appSecrets
    }
}

/// The dispatcher's request to the requester's running app for the daemon-store secrets a start, cutover or arm found
/// missing (the owner check, the five-second deadline and the failure vocabulary stay in the dispatcher). A service that
/// owns the handoff (`DaemonService.ownsAppSecretHandoff`) calls it inside the command that found the secrets missing, so
/// the continuation runs under that command's admission and never as a fresh request.
public final class AppSecretsHandoff: Sendable {
    private let provide: @Sendable (UUID) async throws -> SecretBundle

    public init(_ provide: @escaping @Sendable (UUID) async throws -> SecretBundle) {
        self.provide = provide
    }

    public func request(_ profileID: UUID) async throws -> SecretBundle {
        try await provide(profileID)
    }
}

/// An eligible Wi-Fi reporter's standing (ADR-030 section 3). The dispatcher issues one when an app connection subscribes
/// and revokes it synchronously when the connection ends or its subscription stops, before it tells the service of the
/// loss. A report carries it across the hop to the controller, which counts the reading only while it still holds, in the
/// same actor turn as the commit: a loss is either ordered after the accepted reading (and invalidates it) or refuses it.
public final class WiFiReporterMembership: Sendable {
    private let current = Mutex(true)

    public init() {}

    public var isCurrent: Bool {
        current.withLock { $0 }
    }

    public func revoke() {
        current.withLock { $0 = false }
    }
}

/// Controller integration seam. The controller owns generations and all mutation.
/// Diagnostics MUST honour context.visibleProfileIDs, including when it is empty;
/// opaque archive bytes cannot be filtered after creation by the dispatcher.
public protocol DaemonService: Sendable {
    func ownerUID(for profileID: UUID) async -> uid_t?
    func profileIDs(ownedBy uid: uid_t) async -> Set<UUID>
    /// Owner of persistent lockdown as well as any active intent; nil only when unowned.
    func protectionOwnerUID() async -> uid_t?
    func activeProfileID() async -> UUID?
    func currentSettings() async -> MacGlobalSettings
    func handle(_ request: Request, context: DaemonRequestContext, secrets: consuming SecretBundle?) async -> Reply
    /// Additive CAS port, kept separate from the existing controller request switch.
    func installProfileCAS(_ profile: TunnelProfile, expectedRevision: UInt64?, context: DaemonRequestContext) async -> Reply
    /// Owner-scoped revision read; nil means a new profile.
    func profileRevision(_ id: UUID, context: DaemonRequestContext) async -> Reply
    /// Qualifies status before it crosses the wire, using installed daemon-owned profile data.
    func qualifyStatus(_ status: TunnelStatus, profileID: UUID?) async -> QualifiedDaemonStatus
    /// An eligible Wi-Fi reporter's connection ended or its subscription stopped (ADR-030 section 3).
    func wifiReporterLost() async
    /// Whether the service asks the app for missing secrets itself, through `DaemonRequestContext.appSecrets`, inside the
    /// command that found them missing. Otherwise the dispatcher retries the request with the app's secrets after a
    /// `secretsUnavailable` reply.
    var ownsAppSecretHandoff: Bool { get }
}

public extension DaemonService {
    /// Inert services have no additional platform guarantees to qualify.
    func qualifyStatus(_ status: TunnelStatus, profileID _: UUID?) async -> QualifiedDaemonStatus {
        QualifiedDaemonStatus(status: status, reasons: [])
    }

    /// Services without a profile registry refuse the additive mutation.
    func installProfileCAS(_: TunnelProfile, expectedRevision _: UInt64?, context _: DaemonRequestContext) async -> Reply {
        .error(.malformedMessage)
    }

    /// Services without on-demand ignore reporter changes.
    func wifiReporterLost() async {}

    /// Services that do not own the handoff get the dispatcher's retry.
    var ownsAppSecretHandoff: Bool {
        false
    }

    /// Services without a profile registry refuse revision reads.
    func profileRevision(_: UUID, context _: DaemonRequestContext) async -> Reply {
        .error(.malformedMessage)
    }
}

/// Trusted authorisation facts are resolved per request, so a logout takes effect.
public struct DaemonAuthorisation: Sendable {
    public let isConsoleUser: @Sendable (VerifiedPeerIdentity) async -> Bool
    public let hasAdminRight: @Sendable (Data?, VerifiedPeerIdentity) async -> Bool
    /// The peer carries the app's signing identifier (not the CLI's); evaluated once when the connection is accepted.
    public let isAppClient: @Sendable (VerifiedPeerIdentity) async -> Bool

    /// Denies console, admin and app-only operations unless an explicit policy is supplied.
    public init(
        isConsoleUser: @escaping @Sendable (VerifiedPeerIdentity) async -> Bool = { _ in false },
        hasAdminRight: @escaping @Sendable (Data?, VerifiedPeerIdentity) async -> Bool = { _, _ in false },
        isAppClient: @escaping @Sendable (VerifiedPeerIdentity) async -> Bool = { _ in false },
    ) {
        self.isConsoleUser = isConsoleUser
        self.hasAdminRight = hasAdminRight
        self.isAppClient = isAppClient
    }
}

public extension Request {
    var profileID: UUID? {
        switch self {
        case let .installProfile(document): document.profile.id
        case let .installProfileCAS(profile, _): profile.id
        case let .profileRevision(id): id
        case let .removeProfile(id, _), let .startIntent(id, _, _), let .startCutover(id, _, _), let .stop(id, _),
             let .selectTransport(id, _), let .setStartBeforeLoginIntent(id, _), let .armOnDemand(id, _), let .disarmOnDemand(id): id
        default: nil
        }
    }
}
