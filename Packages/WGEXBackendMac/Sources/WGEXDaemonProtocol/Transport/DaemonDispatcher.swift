// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Authenticates before decoding, then authorises before invoking the controller.
public actor DaemonDispatcher: XPCDaemonTransport {
    public static let maximumPayloadSize = 256 * 1024
    public static let maximumQueuedEvents = 32
    public static let maximumSubscriptionsPerUID = 16

    package struct Connection {
        package let peer: VerifiedPeerIdentity
        package let callbacks: XPCClientCallbacks
        package var clientBuild: Int?
        package var tokens: Double = 64
        package var lastRefill: TimeInterval
        package var subscribed = false
        package var includeLogs = false
        /// The peer carries the app's signing identifier (ADR-030 eligible reporter), fixed at acceptance.
        package var isApp = false
        /// The reporter standing of a subscribed app connection; revoked before the service hears of its loss.
        package var reporter: WiFiReporterMembership?
        package var lastStatusSequence: UInt64 = 0
        package var pump: OrderedEventPump?
    }

    private var recovering = false

    /// Restricts requests while startup reconciliation or its retry is pending.
    public func setRecovering(_ value: Bool) {
        recovering = value
    }

    /// The run's first-publication fence (DEC-011); nil until a composition runs.
    package var startupFence: StartupFence?

    package let service: any DaemonService
    package let authorisation: DaemonAuthorisation
    private let hello: HelloReply
    private let minimumDaemonBuild: Int
    package let secretFailure: @Sendable (DaemonFailure) -> Void
    package let clock: XPCClock
    package let nextStatusSequence: (@Sendable () throws -> UInt64)?
    package var sequence: UInt64 = 0
    package var operationsInFlight = 0
    package var heartbeatTask: Task<Void, Never>?
    package let measureStatus: (@Sendable () async throws -> StatusMeasurement)?
    package struct Publication: Sendable {
        package let event: Event
        package let profileID: UUID?
        package let ownerUID: UInt32?
        package let completion: CheckedContinuation<Void, Never>
    }

    package let publications = AsyncStream<Publication>.makeStream()
    package var publicationTask: Task<Void, Never>?
    package var connections: [UUID: Connection] = [:]

    public init(
        service: any DaemonService,
        daemonVersion: String,
        daemonBuild: Int,
        minimumClientBuild: Int,
        minimumDaemonBuild: Int = 0,
        authorisation: DaemonAuthorisation = DaemonAuthorisation(),
        clock: XPCClock = .continuous,
        nextStatusSequence: (@Sendable () throws -> UInt64)? = nil,
        measureStatus: (@Sendable () async throws -> StatusMeasurement)? = nil,
        secretFailure: @escaping @Sendable (DaemonFailure) -> Void = { _ in },
    ) {
        self.service = service
        self.authorisation = authorisation
        hello = HelloReply(
            daemonVersion: daemonVersion, daemonBuild: daemonBuild,
            protocolVersion: Envelope.currentProtocolVersion, minimumClientBuild: minimumClientBuild,
        )
        self.minimumDaemonBuild = minimumDaemonBuild
        self.clock = clock
        self.nextStatusSequence = nextStatusSequence
        self.measureStatus = measureStatus
        self.secretFailure = secretFailure
    }

    public func accept(peer: VerifiedPeerIdentity, callbacks: XPCClientCallbacks) async throws -> UUID {
        guard peer.codeSigningVerdict == .requirementSatisfied else { throw DaemonError.unauthorised }
        let isApp = await authorisation.isAppClient(peer)
        let id = UUID()
        connections[id] = Connection(peer: peer, callbacks: callbacks, lastRefill: clock.now(), isApp: isApp)
        return id
    }

    public func receive(connectionID: UUID, envelope: Data, secrets: Data?) async -> Data {
        let transient = secrets ?? Data()
        defer { SecretsWireLayout.wipeReceived(transient) }
        let reply: Reply
        do {
            reply = try await dispatch(connectionID, envelope: envelope, secrets: transient)
        } catch let error as DaemonFailure {
            reply = .error(error.wireError())
        } catch let error as DaemonError {
            reply = .error(error)
        } catch {
            reply = .error(.malformedMessage)
        }
        do {
            let encoded = try WireCodec.encode(reply)
            guard encoded.count <= Self.maximumPayloadSize else {
                return Self.errorBytes(.messageTooLarge(encoded.count))
            }
            return encoded
        } catch {
            return Self.errorBytes(.malformedMessage)
        }
    }

    deinit { heartbeatTask?.cancel(); publications.continuation.finish(); publicationTask?.cancel() }

    private static func errorBytes(_ error: DaemonError) -> Data {
        // A small, fixed enum is always encodable; never include arbitrary error descriptions.
        (try? WireCodec.encode(Reply.error(error))) ?? Data()
    }

    private func consumeToken(_ id: UUID) throws -> Connection {
        guard var connection = connections[id] else { throw DaemonError.disconnected }
        let now = clock.now()
        connection.tokens = min(64, connection.tokens + max(0, now - connection.lastRefill) * 64)
        connection.lastRefill = max(now, connection.lastRefill)
        guard connection.tokens >= 1 else {
            connections[id] = connection
            throw DaemonError.rateLimited
        }
        connection.tokens -= 1
        connections[id] = connection
        return connection
    }

    private func dispatch(_ id: UUID, envelope data: Data, secrets: Data) async throws -> Reply {
        let connection = try consumeToken(id)
        var envelope = try Envelope.decode(data)
        try validatePayload(envelope, byteCount: data.count, secrets: secrets)
        if let reply = try handshake(envelope.body, connectionID: id) {
            return reply
        }
        guard let build = connection.clientBuild else { throw DaemonError.handshakeRequired }
        try validateSecretMethod(envelope.body, secrets: secrets)
        if recovering {
            try await validateRecoveryRequest(envelope.body)
        }
        try await holdForFirstPublication(envelope.body)
        if case let .stopCurrent(reason) = envelope.body {
            guard let active = await service.activeProfileID() else { return .ok }
            envelope.body = .stop(profileID: active, reason: reason)
        }
        var context = try await authorise(envelope, connection: connection, build: build)
        guard connections[id] != nil else { throw DaemonError.disconnected }
        if case let .subscribeEvents(includeLogs) = envelope.body {
            try subscribe(id, includeLogs: includeLogs)
            return .ok
        }
        // ADR-030 section 3: only a subscribed reporter's reading counts; any other report is ignored.
        if case .reportWiFiNetwork = envelope.body {
            guard connections[id]?.subscribed == true else { return .ok }
            context.wifiReporter = connections[id]?.reporter
        }
        return try await trackedRoute(envelope.body, context: context, secrets: secrets)
    }

    private func trackedRoute(_ request: Request, context: DaemonRequestContext, secrets: Data) async throws -> Reply {
        let tracksOperation = switch request {
        case .status, .statusTelemetry, .protectionReasons, .profileRevision, .statistics, .logs, .secureInstallStatus, .diagnostics,
             .reportWiFiNetwork:
            false
        default: true
        }
        if tracksOperation {
            operationsInFlight += 1
        }
        defer {
            if tracksOperation {
                operationsInFlight -= 1
            }
        }
        let reply = try await route(request, context: context, secrets: secrets)
        if case let .status(status) = reply {
            return try await statusReply(status, uid: context.peer.uid)
        }
        return reply
    }

    private func validatePayload(_ envelope: Envelope, byteCount: Int, secrets: Data) throws {
        guard secrets.count <= Self.maximumPayloadSize else { throw DaemonError.messageTooLarge(secrets.count) }
        guard try WireCodec.encode(envelope.body).count <= Self.maximumPayloadSize else {
            throw DaemonError.messageTooLarge(byteCount)
        }
        if case .hello = envelope.body, !secrets.isEmpty {
            throw DaemonError.malformedMessage
        }
        let profile: TunnelProfile
        switch envelope.body {
        case let .installProfile(document): profile = document.profile
        case let .installProfileCAS(document, _): profile = document
        default: return
        }
        let refs = [profile.secrets.privateKey] + Array(profile.secrets.presharedKeys.values)
            + Array(profile.secrets.carrierCredentials.values)
        guard refs.allSatisfy({
            if case .daemonStore = $0 {
                true
            } else {
                false
            }
        }) else { throw DaemonError.malformedMessage }
    }

    private func handshake(_ request: Request, connectionID: UUID) throws -> Reply? {
        guard hello.daemonBuild >= minimumDaemonBuild else { throw DaemonError.downgradeDetected }
        guard case let .hello(_, build) = request else { return nil }
        guard build >= hello.minimumClientBuild, build >= hello.daemonBuild else {
            connections[connectionID]?.clientBuild = nil
            throw DaemonError.downgradeDetected
        }
        connections[connectionID]?.clientBuild = build
        return .hello(hello)
    }

    private func authorise(_ envelope: Envelope, connection: Connection, build: Int) async throws -> DaemonRequestContext {
        let owner: uid_t? = if let profileID = envelope.body.profileID {
            await service.ownerUID(for: profileID)
        } else {
            switch envelope.body {
            case .status, .statusTelemetry, .protectionReasons, .statistics, .openCaptiveWindow, .extendCaptiveWindow, .setGlobalSettings,
                 .confirmCutover, .abortCutover:
                await service.protectionOwnerUID()
            default: connection.peer.uid
            }
        }
        let decision = await AuthorisationTable.decide(
            request: envelope.body, callerUID: connection.peer.uid,
            isConsoleUser: authorisation.isConsoleUser(connection.peer),
            hasAdminRight: authorisation.hasAdminRight(envelope.authorization, connection.peer),
            ownerUID: owner, currentSettings: service.currentSettings(), clientIsNewer: build > hello.daemonBuild,
            isAppClient: connection.isApp,
        )
        if case let .deny(reason) = decision {
            throw DaemonError.notAuthorised(reason)
        }
        return await DaemonRequestContext(
            peer: connection.peer, visibleProfileIDs: service.profileIDs(ownedBy: connection.peer.uid), clientBuild: build,
            expectedGeneration: envelope.expectedGeneration,
        )
    }

    private func route(_ original: Request, context: DaemonRequestContext, secrets: Data) async throws -> Reply {
        if let reply = try await statusRead(original, context: context) {
            return reply
        }
        if case let .installProfileCAS(profile, expectedRevision) = original {
            return await service.installProfileCAS(profile, expectedRevision: expectedRevision, context: context)
        }
        if case let .profileRevision(id) = original {
            return await service.profileRevision(id, context: context)
        }
        var request = original
        let visible = context.visibleProfileIDs
        if case var .diagnostics(options) = request {
            options.profileIDs = options.profileIDs.isEmpty
                ? visible.sorted { $0.uuidString < $1.uuidString }
                : options.profileIDs.filter { visible.contains($0) }
            request = .diagnostics(options)
        }
        let bundle: SecretBundle? = secrets.isEmpty ? nil : try SecretsWireLayout.decodeReceived(secrets)
        let reply = try await serve(request, context: context, secrets: bundle)
        if case let .logs(lines) = reply {
            return .logs(lines.filter { line in line.profileID.map { visible.contains($0) } ?? true })
        }
        if case let .status(status) = reply {
            return await .status(service.qualifyStatus(status, profileID: service.activeProfileID()).status)
        }
        return reply
    }
}

public extension DaemonDispatcher {
    /// A subscribed app connection is an eligible Wi-Fi reporter; its loss is a coordinator trigger (ADR-030 section 3).
    func disconnect(connectionID: UUID) async {
        guard let removed = connections.removeValue(forKey: connectionID) else { return }
        removed.reporter?.revoke()
        removed.pump?.close()
        if removed.isApp, removed.subscribed {
            await service.wifiReporterLost()
        }
    }
}
