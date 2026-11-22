// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// Mac backend. The injected transport is the only communication channel.
public actor DaemonClient: TunnelBackend {
    public nonisolated let capabilities: BackendCapabilities = [
        .killSwitch, .lockdown, .captiveWindow, .startBeforeLogin, .transportSwitching, .allowLAN, .onDemand,
    ]

    package let transport: any XPCTransport
    private let version: String
    private let build: Int
    /// Build participating in update negotiation.
    public var clientBuild: Int {
        build
    }

    private let minimumDaemonBuild: Int
    package let clock: XPCClock
    private let secretStore: any SecretStore?
    package let statuses = StatusBroadcast()
    private var connectionState: DaemonConnectionState = .disconnected(lastError: nil)
    private var connectionObservers: [UUID: AsyncStream<DaemonConnectionState>.Continuation] = [:]
    private var wifiRequestObservers: [UUID: AsyncStream<String>.Continuation] = [:]
    package var connected = false
    private var recoverySubscriptionPending = false
    /// The daemon cannot decode `statusTelemetry` (an older protocol-8 build); reset for each daemon instance.
    package var telemetryUnsupported = false
    package var sequenceFloor: UInt64 = 0
    package var sameInstanceEvidence = false
    private var daemonInstanceID: UUID?
    private var lastHello: HelloReply?
    package var stopped = false
    package var epoch = 0
    private var connectionTask: Task<HelloReply, any Error>?
    package var reconnectTask: Task<Void, Never>?
    package var pendingIntent = UUID()
    package var surfaceVisible = true
    package var stalenessTask: Task<Void, Never>?
    private var eventPump: OrderedEventPump?
    package var lastMeasuredStatus: TunnelStatus?
    package var connectionStartedAt = Date()
    package let jitter: @Sendable () -> Double
    private var secretReferences: [UUID: AppSecretReferences] = [:]
    private var daemonDocuments: [UUID: TunnelProfile] = [:]
    package var revisions: [UUID: UInt64] = [:]
    package var conflictedProfiles: Set<UUID> = []
    public package(set) var lastGeneration: Generation?

    public init(
        transport: any XPCTransport,
        clientVersion: String,
        clientBuild: Int,
        minimumDaemonBuild: Int = ProtocolCompatibility.minimumDaemonBuild,
        secretStore: any SecretStore? = nil,
        clock: XPCClock = .continuous,
        jitter: @escaping @Sendable () -> Double = { Double.random(in: 0.8 ... 1.2) },
        surfaceVisible: Bool = true,
    ) {
        self.transport = transport
        version = clientVersion
        build = clientBuild
        self.minimumDaemonBuild = minimumDaemonBuild
        self.secretStore = secretStore
        self.clock = clock
        self.jitter = jitter
        self.surfaceVisible = surfaceVisible
    }

    /// App-only account registration; account references never cross XPC.
    public func setSecretReferences(_ references: AppSecretReferences, for profileID: UUID) {
        secretReferences[profileID] = references
    }

    @discardableResult
    public func connect() async throws -> HelloReply {
        try await connect(observing: true)
    }

    /// `observing: false` leaves the first status read to the caller, so connection setup spends no sequence number the caller
    /// would never see (DEC-011, M03-T01).
    package func connect(observing: Bool) async throws -> HelloReply {
        if connected, let lastHello {
            return lastHello
        }
        if let connectionTask {
            return try await connectionTask.value
        }
        stopped = false
        labLog("connecting")
        publishConnection(.connecting)
        let attemptEpoch = epoch
        let task = Task { try await self.establish(epoch: attemptEpoch, observing: observing) }
        connectionTask = task
        defer {
            if epoch == attemptEpoch {
                connectionTask = nil
            }
        }
        do { return try await task.value }
        catch {
            if epoch == attemptEpoch {
                publishConnection(.disconnected(lastError: DaemonConnectionFailure(error)))
            }
            throw error
        }
    }

    /// Raw typed command path for CLI and app settings. Mutations are never replayed automatically.
    public func request(_ request: Request, authorization: Data? = nil, expectedGeneration: Generation? = nil) async throws -> Reply {
        if [.stop, .stopCurrent, .abortCutover].contains(request.kind) {
            pendingIntent = UUID()
        }
        try await ready()
        return try await exchange(request, authorization: authorization, expectedGeneration: expectedGeneration)
    }

    /// Connects when needed and retries a subscription that recovery refused.
    package func ready() async throws {
        if !connected {
            _ = try await connect()
        }
        if recoverySubscriptionPending {
            do {
                _ = try await exchange(.subscribeEvents(includeLogs: false))
                recoverySubscriptionPending = false
            } catch DaemonError.recovering { /* Status and recovery-safe commands remain available. */ }
        }
    }

    package func exchange(
        _ request: Request, authorization: Data? = nil, expectedGeneration: Generation? = nil, secrets: Data? = nil,
    ) async throws -> Reply {
        let envelope = try Envelope(authorization: authorization, expectedGeneration: expectedGeneration, body: request).encoded()
        let requestEpoch = epoch
        let reply: Reply
        do { reply = try await WireCodec.decode(Reply.self, from: transport.send(envelope, secrets: secrets)) }
        catch {
            if (error as? DaemonError) == .disconnected {
                interrupted(epoch: requestEpoch)
            }
            throw error
        }
        if case let .error(error) = reply {
            if error == .secureInstallRequired {
                publishConnection(.secureInstallRequired(daemonBuild: lastHello?.daemonBuild ?? build))
            }
            throw error
        }
        return reply
    }

    /// Conflicts require explicit refreshRevision; unknown outcomes refresh before a later save.
    public func install(_ profile: TunnelProfile) async throws(TunnelError) {
        var document = profile
        let bindings = secretReferences[profile.id]
        document.secrets = SecretReferences(
            privateKey: .daemonStore(id: bindings?.privateKey.id ?? profile.id),
            presharedKeys: Dictionary(uniqueKeysWithValues: profile.secrets.presharedKeys.map { peer, reference in
                (peer, Self.daemonReference(
                    reference,
                    account: bindings?.presharedKeys[peer],
                    previous: daemonDocuments[profile.id]?.secrets.presharedKeys[peer],
                ))
            }),
            carrierCredentials: Dictionary(uniqueKeysWithValues: profile.secrets.carrierCredentials.map { transport, reference in
                (transport, Self.daemonReference(
                    reference,
                    account: bindings?.carrierCredentials[transport],
                    previous: daemonDocuments[profile.id]?.secrets.carrierCredentials[transport],
                ))
            }),
        )
        document.original = nil
        do {
            try await installDocument(document)
            daemonDocuments[profile.id] = document
        } catch DaemonError.tunnel(.revisionConflict) {
            conflictedProfiles.insert(profile.id); throw .revisionConflict
        } catch { throw Self.map(error) }
    }

    public func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
        do {
            _ = try await request(.removeProfile(id, purgeSecrets: purgeSecrets))
            secretReferences.removeValue(forKey: id)
            revisions.removeValue(forKey: id)
            conflictedProfiles.remove(id)
            daemonDocuments.removeValue(forKey: id)
        } catch { throw Self.map(error) }
    }

    public func start(_ id: UUID, transport selection: TransportID?) async throws(TunnelError) {
        let intent = UUID()
        pendingIntent = intent
        do {
            if !connected {
                _ = try await connect()
            }
            guard pendingIntent == intent else { throw DaemonError.tunnel(.cancelled) }
            guard lastHello?.daemonBuild == build else { throw DaemonError.disconnected }
            var secrets = try await secretData(id)
            defer { secrets.resetBytes(in: 0 ..< secrets.count) }
            guard pendingIntent == intent else { throw DaemonError.tunnel(.cancelled) }
            let reply = try await exchange(
                .startIntent(profileID: id, transport: selection, hasSecrets: !secrets.isEmpty),
                secrets: secrets.isEmpty ? nil : secrets,
            )
            guard case let .started(generation) = reply else { throw DaemonError.malformedMessage }
            if pendingIntent != intent {
                _ = try? await exchange(.stop(profileID: id, reason: .userRequested), expectedGeneration: generation)
                throw DaemonError.tunnel(.cancelled)
            }
            lastGeneration = generation
        } catch { throw Self.map(error) }
    }

    public func stop(_ id: UUID) async throws(TunnelError) {
        do { _ = try await request(.stop(profileID: id, reason: .userRequested)) }
        catch { throw Self.map(error) }
    }

    private func interrupted(epoch callbackEpoch: Int) {
        guard callbackEpoch == epoch, !stopped else { return }
        epoch += 1
        pendingIntent = UUID()
        labLog("connection interrupted")
        publishConnection(.disconnected(lastError: .unavailable))
        connected = false
        lastHello = nil
        connectionTask?.cancel()
        connectionTask = nil
        publishUnavailable()
        scheduleReconnect()
    }

    public func disconnect() async {
        stopped = true
        pendingIntent = UUID()
        stalenessTask?.cancel(); stalenessTask = nil
        eventPump?.close(); eventPump = nil
        publishUnavailable()
        publishConnection(.disconnected(lastError: nil))
        epoch += 1
        connected = false
        lastHello = nil
        reconnectTask?.cancel()
        reconnectTask = nil
        connectionTask?.cancel()
        connectionTask = nil
        await transport.invalidate()
    }

    deinit { stalenessTask?.cancel(); reconnectTask?.cancel(); connectionTask?.cancel(); eventPump?.close() }
}

extension DaemonClient {
    private func establish(epoch attemptEpoch: Int, observing: Bool) async throws -> HelloReply {
        do {
            let pump = OrderedEventPump { [weak self] bytes in await self?.receive(bytes, epoch: attemptEpoch) }
            eventPump?.close(); eventPump = pump
            try await transport.connect(callbacks: XPCClientCallbacks(
                event: { bytes in pump.enqueue(bytes) },
                provideSecrets: { [weak self] id in
                    guard let self else { throw DaemonError.secretsUnavailable }
                    return try await provideSecrets(id, epoch: attemptEpoch)
                },
                invalidated: { [weak self] in await self?.interrupted(epoch: attemptEpoch) },
            ))
            let reply = try await exchange(.hello(clientVersion: version, clientBuild: build))
            guard case let .hello(hello) = reply else { throw DaemonError.malformedMessage }
            guard hello.protocolVersion == Envelope.currentProtocolVersion else {
                throw DaemonError.unsupportedProtocolVersion(hello.protocolVersion)
            }
            guard hello.daemonBuild >= minimumDaemonBuild, build >= hello.minimumClientBuild, build >= hello.daemonBuild else {
                throw DaemonError.downgradeDetected
            }
            guard attemptEpoch == epoch, !stopped else { throw DaemonError.disconnected }
            if daemonInstanceID != hello.instanceID {
                daemonInstanceID = hello.instanceID
                sequenceFloor = 0
                sameInstanceEvidence = false
                telemetryUnsupported = false
            }
            connected = true
            connectionStartedAt = Date()
            beginStalenessClock()
            do {
                _ = try await exchange(.subscribeEvents(includeLogs: false))
                recoverySubscriptionPending = false
            } catch DaemonError.recovering {
                recoverySubscriptionPending = true
            }
            let status = observing ? try await initialStatus() : nil
            guard attemptEpoch == epoch, !stopped else { throw DaemonError.disconnected }
            if let status {
                acceptStatus(status)
            }
            lastHello = hello
            labLog("connected")
            publishConnection(.connected(daemonBuild: hello.daemonBuild))
            return hello
        } catch {
            connected = false
            await transport.invalidate()
            throw error
        }
    }

    private static func daemonReference(_ reference: SecretRef, account: SecretID?, previous: SecretRef?) -> SecretRef {
        if let account {
            return .daemonStore(id: account.id)
        }
        if let previous {
            return previous
        }
        if case .daemonStore = reference {
            return reference
        }
        return .daemonStore(id: UUID())
    }

    // M1-12: explicit module-only access satisfies SwiftLint without exposing this helper to the package.
    // swiftformat:disable:next redundantInternal
    internal func secretData(_ id: UUID) async throws -> Data {
        guard let secretStore, let references = secretReferences[id] else { return Data() }
        do {
            let wire = try await references.wireBytes(from: secretStore, profileID: id)
            guard wire.count <= DaemonDispatcher.maximumPayloadSize else { throw DaemonError.messageTooLarge(wire.count) }
            return wire.withUnsafeBytes { Data($0) }
        } catch {
            labLog("secrets unavailable")
            throw DaemonError.secretsUnavailable
        }
    }

    private func provideSecrets(_ id: UUID, epoch callbackEpoch: Int) async throws -> Data {
        guard connected, callbackEpoch == epoch, lastHello?.daemonBuild == build else { throw DaemonError.handshakeRequired }
        let bytes = try await secretData(id)
        guard !bytes.isEmpty else { throw DaemonError.secretsUnavailable }
        return bytes
    }

    private func receive(_ bytes: Data, epoch callbackEpoch: Int) async {
        guard connected, callbackEpoch == epoch, let event = try? WireCodec.decode(Event.self, from: bytes) else { return }
        labLog("event received")
        switch event {
        case let .status(status): acceptStatus(status)
        case .subscriptionLost:
            labLog("subscription lost")
            do {
                _ = try await exchange(.subscribeEvents(includeLogs: false))
                try await refreshStatus()
            } catch { /* Interruption owns retry; the staleness clock remains independent. */ }
        case let .wifiNetworkRequested(interfaceName):
            for observer in wifiRequestObservers.values {
                observer.yield(interfaceName)
            }
        case .statistics, .log, .needsSecrets: break
        }
    }
}

public extension DaemonClient {
    /// Interface names the daemon asks the app to read (ADR-030 section 3); the app answers with ``reportWiFiNetwork(_:)``.
    func wifiNetworkRequests() -> AsyncStream<String> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<String>.makeStream(bufferingPolicy: .bufferingNewest(8))
        wifiRequestObservers[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeWiFiRequestObserver(id) }
        }
        return stream
    }

    private func removeWiFiRequestObserver(_ id: UUID) {
        wifiRequestObservers.removeValue(forKey: id)
    }

    /// Arms on-demand; secrets travel in the separate argument as for start, or through the app handoff from the CLI.
    func armOnDemand(_ id: UUID) async throws {
        _ = try await connect()
        guard lastHello?.daemonBuild == build else { throw DaemonError.disconnected }
        var secrets = try await secretData(id)
        defer { secrets.resetBytes(in: 0 ..< secrets.count) }
        guard case .ok = try await exchange(
            .armOnDemand(profileID: id, hasSecrets: !secrets.isEmpty),
            secrets: secrets.isEmpty ? nil : secrets,
        ) else { throw DaemonError.malformedMessage }
    }

    /// Disarms on-demand, stopping the profile if it is intended.
    func disarmOnDemand(_ id: UUID) async throws {
        guard case .ok = try await request(.disarmOnDemand(profileID: id)) else { throw DaemonError.malformedMessage }
    }

    /// Relays the app's Wi-Fi reading; the daemon holds it in memory only.
    func reportWiFiNetwork(_ observation: WiFiObservation) async throws {
        guard case .ok = try await request(.reportWiFiNetwork(observation)) else { throw DaemonError.malformedMessage }
    }
}

public extension DaemonClient {
    /// Replays the latest state to each observer, including late app scene subscribers.
    func connectionStates() -> AsyncStream<DaemonConnectionState> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<DaemonConnectionState>.makeStream(bufferingPolicy: .bufferingNewest(64))
        connectionObservers[id] = continuation
        continuation.yield(connectionState)
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeConnectionObserver(id) }
        }
        return stream
    }

    private func removeConnectionObserver(_ id: UUID) {
        connectionObservers.removeValue(forKey: id)
    }

    package func secureInstallVerified() {
        if case .secureInstallRequired = connectionState, connected, let lastHello {
            publishConnection(.connected(daemonBuild: lastHello.daemonBuild))
        }
    }

    /// Replays actual client connectivity after a UI-only update workflow ends.
    func republishConnectionState() {
        publishConnection(connectionState)
    }

    package func connectionStateSnapshot() -> DaemonConnectionState {
        connectionState
    }

    package func publishConnection(_ state: DaemonConnectionState) {
        connectionState = state
        for observer in connectionObservers.values {
            observer.yield(state)
        }
    }

    /// Startup intent carries secrets separately, exactly like startIntent.
    func setStartBeforeLogin(_ id: UUID, enabled: Bool) async throws {
        _ = try await connect()
        guard lastHello?.daemonBuild == build else { throw DaemonError.disconnected }
        var secrets = enabled ? try await secretData(id) : Data()
        defer { secrets.resetBytes(in: 0 ..< secrets.count) }
        guard case .ok = try await exchange(
            .setStartBeforeLoginIntent(profileID: id, enabled: enabled),
            secrets: secrets.isEmpty ? nil : secrets,
        ) else { throw DaemonError.malformedMessage }
    }
}
