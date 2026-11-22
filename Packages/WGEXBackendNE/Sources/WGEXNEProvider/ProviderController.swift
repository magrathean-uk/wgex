// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXEngineInterface

/// Extension lifecycle actor. All effects pass through seams; no engine binary is linked here.
public actor ProviderController {
    public typealias EngineFactory = @Sendable (EngineConfiguration) throws -> any EngineControlling
    public private(set) var status = TunnelStatus.idle
    public private(set) var lastStopReason: Int?
    public private(set) var typedStopReason: ProviderStopReason?
    public private(set) var statisticsTicks = 0
    private let system: any ProviderSystem
    private let profiles: any ProviderProfileLoading
    private let secrets: any ProviderSecretLoading
    private let resolver: any ProviderEndpointResolving
    private let clock: any ProviderClock
    private let pathFailureLog: @Sendable (String) -> Void
    private let logSink: any ProviderLogSink
    private var logRing = ProviderLogRing()
    private var logTask: Task<Void, Never>?
    private let platform: ProfilePlatform
    private let makeEngine: EngineFactory
    private var engine: any EngineControlling?
    private var startTask: Task<Void, any Error>?
    private var profile: TunnelProfile?
    private var generation = Generation.initial
    private var revision: UInt64 = 0
    private var activeRevision: UInt64?
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var sleepInstant: TimeInterval?
    private var sleeping = false
    private var quiesced = false
    private var lastHandshake: Date?
    private var path = ProviderPath(satisfied: true)
    /// The path whose last resolve failed: an identical update retries the resolve instead of being ignored.
    private var unresolvedPath: ProviderPath?
    private var eventTask: Task<Void, Never>?
    private var pathTask: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?
    private var offlineTask: Task<Void, Never>?
    private var reassertTask: Task<Void, Never>?
    /// What NE believes: set after the first successful start, cleared only by a stop, `fail()` or a failed initial start.
    /// Unlike an engine being up, it survives a reload's teardown and a superseded start, so overlapping reloads stay reloads.
    private var connected = false
    private var cancelledGeneration: Generation?
    private var subscriptionTask: Task<Void, Never>?
    private var subscribedStats: TunnelStatistics?
    private var subscriptionInterval: TimeInterval?

    public init(
        system: any ProviderSystem, profiles: any ProviderProfileLoading, secrets: any ProviderSecretLoading,
        resolver: any ProviderEndpointResolving, clock: any ProviderClock = SystemProviderClock(),
        platform: ProfilePlatform, engineFactory: @escaping EngineFactory,
        logSink: any ProviderLogSink = UnifiedProviderLogSink(),
    ) {
        self.init(
            system: system, profiles: profiles, secrets: secrets, resolver: resolver, clock: clock, platform: platform,
            engineFactory: engineFactory, pathFailureLog: { _ in }, logSink: logSink,
        )
    }

    /// `pathFailureLog` also receives the fixed text of a path change that failed to resolve; a cancelled resolve is
    /// never reported. Every line, that one included, goes to `logSink`.
    package init(
        system: any ProviderSystem, profiles: any ProviderProfileLoading, secrets: any ProviderSecretLoading,
        resolver: any ProviderEndpointResolving, clock: any ProviderClock, platform: ProfilePlatform,
        engineFactory: @escaping EngineFactory, pathFailureLog: @escaping @Sendable (String) -> Void,
        logSink: any ProviderLogSink = UnifiedProviderLogSink(),
    ) {
        self.system = system; self.profiles = profiles; self.secrets = secrets; self.resolver = resolver
        self.clock = clock; self.platform = platform; makeEngine = engineFactory; self.pathFailureLog = pathFailureLog
        self.logSink = logSink
    }

    public func startTunnel(profileID: UUID) async throws {
        revision &+= 1
        let token = revision
        startTask?.cancel()
        let work = Task { try await self.performStart(profileID: profileID, token: token) }
        startTask = work
        defer {
            if token == revision {
                startTask = nil
            }
        }
        try await withTaskCancellationHandler { try await work.value } onCancel: { work.cancel() }
    }

    private func performStart(profileID: UUID, token: UInt64) async throws {
        await acquire()
        defer { release() }
        guard token == revision else { throw TunnelError.cancelled }
        // A reload of a connected tunnel keeps the old settings until the new ones replace them (ENGINE-03).
        let reload = connected
        await cleanup(clearingSettings: !reload)
        generation = generation.next()
        status.phase = .preparing(generation)
        log(reload ? "Tunnel reloading" : "Tunnel starting")
        do {
            let loaded = try await profiles.load(profileID)
            guard !loaded.validate().contains(where: { $0.severity == .error }) else {
                throw TunnelError.invalidConfiguration(.invalidProfile)
            }
            let keys = try await secrets.load(for: loaded)
            let resolver = resolver
            let interfaceIndex = path.interfaceIndex
            let endpoints = try await withProviderDeadlineValue(clock: clock, seconds: 10) {
                try await resolver.resolve(loaded, interfaceIndex: interfaceIndex)
            }
            // Under Force all traffic (iPhone and iPad) no name is looked up (M08-R01 F2).
            let excludedNames = NESettingsGenerator.appliesExclusions(loaded, platform: platform) ? loaded.exclusions.hostNames : []
            let found = await resolver.resolveExclusions(excludedNames, interfaceIndex: interfaceIndex)
            try check(token)
            profile = loaded
            status.phase = .configuring(generation)
            status.unresolvedExclusions = excludedNames.filter { found[$0]?.isEmpty != false }
            // Ports need the Mac packet filter (DEC-126) and Force all traffic stops the rest; both are only reported here.
            (status.unsupportedExclusionPorts, status.forceAllIgnoredExclusions) = NESettingsGenerator.ignored(loaded, platform: platform)
            let settings = try NESettingsGenerator.generate(
                loaded, platform: platform, resolvedExclusions: found.values.flatMap(\.self),
            )
            let system = system
            try await withProviderDeadline(clock: clock, seconds: 10) { try await system.apply(settings) }
            try check(token)
            try await configureEngine(loaded, keys: keys, endpoints: endpoints, token: token)
            try await startMonitoring()
            activeRevision = token
            connected = true
            status.phase = .active(generation); status.protection = .unknown
            log("Tunnel active")
            startStatsTimer()
        } catch {
            // An initial start throws and NE handles it; a failed reload leaves NE connected, so it ends the tunnel itself.
            if reload, token == revision {
                throw await fail(error)
            }
            // A start superseded while NE is connected leaves the old settings for the newer start or the stop to replace.
            let superseded = token != revision
            await cleanup(clearingSettings: !(superseded && connected))
            let failure = Self.failure(error)
            status.phase = .failed(failure, blockedByPolicy: false, needsSecrets: failure == .secretsUnavailable)
            log("Tunnel start failed: \(ProviderLogText.failure(failure))")
            throw failure
        }
    }

    public func stopTunnel(reason: Int) async {
        revision &+= 1
        startTask?.cancel(); startTask = nil
        await acquire()
        defer { release() }
        connected = false
        lastStopReason = reason
        let typed = ProviderStopReason(rawValue: reason)
        typedStopReason = typed
        log("Tunnel stopping: reason \(reason) (\(String(describing: typed)))")
        status.phase = .stopping(generation, reason: typed.lifecycleReason)
        // An unstructured child deliberately shields teardown from caller cancellation.
        let shield = Task { await self.cleanup() }
        await shield.value
        status = .idle
        log("Tunnel stopped")
    }

    public func sleep() async {
        guard isActive else { return }
        await acquire()
        defer { release() }
        guard isActive, engine != nil else { return }
        sleepInstant = clock.continuousNow; sleeping = true
        log("Sleep: timers paused")
        statsTask?.cancel(); statsTask = nil
        subscriptionTask?.cancel(); subscriptionTask = nil
        await system.quiesceTimers(true)
    }

    /// Only a wake that follows a recorded sleep of this generation acts. A failing engine call ends the tunnel here
    /// (cleanup and cancel), so the method does not throw for it; the signature stays for the extension shells.
    public func wake() async throws {
        guard isActive, sleeping else { return }
        await acquire()
        defer { release() }
        guard isActive, sleeping, let engine else { return }
        let delta = sleepInstant.map { clock.continuousNow - $0 } ?? 0
        let age = lastHandshake.map { clock.wallNow.timeIntervalSince($0) } ?? .infinity
        sleepInstant = nil; sleeping = false
        log("Wake")
        await system.quiesceTimers(quiesced)
        do {
            try await engine.bumpSockets(v4: path.interfaceIndex, v6: path.interfaceIndex)
            if age > 110 || delta > 5 {
                await beginReasserting(.wake)
                try await engine.forceHandshake()
            }
        } catch {
            await fail(error)
            return
        }
        if !quiesced {
            startStatsTimer()
            if let subscriptionInterval {
                startSubscription(interval: subscriptionInterval)
            }
        }
    }

    /// The lifecycle lock is held only to read and to apply; the resolve between them runs unlocked so stop, sleep and
    /// wake never queue behind it. A result is applied only if the generation and the path are unchanged (ENGINE-08).
    public func pathChanged(_ next: ProviderPath) async throws {
        guard isActive, let pending = await beginPathChange(next) else { return }
        let resolver = resolver
        let profile = pending.profile
        let endpoints: [PublicKey: Endpoint]
        do {
            endpoints = try await withProviderDeadlineValue(clock: clock, seconds: 10) {
                try await resolver.resolve(profile, interfaceIndex: next.interfaceIndex)
            }
        } catch {
            // A failed or timed-out resolve still moves the sockets to the new interface, as the official app does.
            if !Self.isCancellation(error, taskCancelled: Task.isCancelled) {
                await bumpAfterFailedResolve(next, generation: pending.generation)
            }
            throw error
        }
        await applyPathChange(next, generation: pending.generation, endpoints: endpoints)
    }

    /// Fixed log text for a path change that did not apply; nil when a stop or a newer path cancelled the resolve, which is
    /// not a failure. No endpoint or key material is ever included.
    package static func pathChangeFailureLog(_ error: any Error, taskCancelled: Bool) -> String? {
        isCancellation(error, taskCancelled: taskCancelled) ? nil : "Path change not applied: endpoint resolution failed"
    }

    private static func isCancellation(_ error: any Error, taskCancelled: Bool) -> Bool {
        taskCancelled || error is CancellationError || (error as? TunnelError) == .cancelled
    }

    public func statistics() async throws -> TunnelStatistics {
        guard let engine else { throw TunnelError.backendUnavailable }
        return try await engine.statistics()
    }

    public func handle(_ data: Data) async -> Data? {
        do {
            let message = try ProviderCodec.decode(ProviderMessage.self, from: data)
            let reply: ProviderReply
            switch message {
            case .status: reply = .status(status)
            case .statistics: reply = try await .statistics(statistics())
            case let .subscribeStats(interval):
                try subscribe(interval: interval)
                reply = .ok
            case .unsubscribeStats:
                subscriptionTask?.cancel(); subscriptionTask = nil; subscribedStats = nil; subscriptionInterval = nil; reply = .ok
            case let .reload(id): try await startTunnel(profileID: id); reply = .ok
            case let .setTransport(spec):
                try await setTransport(spec); reply = .ok
            case let .logs(since):
                reply = .logs(logRing.lines(since: since))
            }
            return try ProviderCodec.encode(reply)
        } catch { return try? ProviderCodec.encode(ProviderReply.error(Self.failure(error))) }
    }

    /// Latest sample from the provider's subscribed timer; no timer exists without subscription.
    public func subscriptionSample() -> TunnelStatistics? {
        subscribedStats
    }
}

private extension ProviderController {
    var isActive: Bool {
        guard activeRevision == revision else { return false }
        return switch status.phase {
        case .active, .reasserting: true
        default: false
        }
    }

    func configureEngine(
        _ loaded: TunnelProfile, keys: borrowing ParsedSecrets, endpoints: [PublicKey: Endpoint], token: UInt64,
    ) async throws {
        let descriptor = try await system.findUTunDescriptor()
        guard descriptor >= 0 else { throw TunnelError.backendUnavailable }
        try check(token)
        let created = try makeEngine(EngineConfiguration(
            tun: .networkExtension(descriptor: descriptor), mobileQuirks: true, processLimits: .constrained,
        ))
        engine = created
        let document = try UAPIEncoder.fullConfiguration(loaded, secrets: keys, endpoints: endpoints)
        // EngineConfiguration.mobileQuirks applies DisableSomeRoaming after every setConfiguration.
        try await created.setConfiguration(document)
        try check(token)
        try await created.up()
        try check(token)
    }

    func startMonitoring() async throws {
        guard let engine else { throw TunnelError.backendUnavailable }
        let events = await engine.events
        let current = generation
        eventTask = Task { [weak self] in
            for await event in events {
                guard !Task.isCancelled else { break }
                await self?.engineEvent(event, generation: current)
            }
        }
        let logs = await engine.logs
        logTask = Task { [weak self] in
            for await line in logs {
                guard !Task.isCancelled else { break }
                await self?.engineLog(line, generation: current)
            }
        }
        let paths = await system.paths()
        pathTask = Task { [weak self] in
            for await path in paths {
                guard !Task.isCancelled else { break }
                do { try await self?.pathChanged(path) }
                catch {
                    if let message = ProviderController.pathChangeFailureLog(error, taskCancelled: Task.isCancelled) {
                        self?.pathFailureLog(message)
                        await self?.log(message)
                    }
                }
            }
        }
    }

    private func beginPathChange(_ next: ProviderPath) async -> (generation: Generation, profile: TunnelProfile)? {
        await acquire()
        defer { release() }
        guard isActive, engine != nil, let profile else { return nil }
        let previous = path
        path = next
        if !next.satisfied {
            if previous.satisfied {
                log("Path unsatisfied")
                let deadline = clock.continuousNow + 30
                let clock = clock
                let current = generation
                offlineTask?.cancel()
                offlineTask = Task { [weak self] in
                    do {
                        try await clock.sleep(until: deadline)
                        // Strictly more than 30 seconds, rather than prematurely at the boundary.
                        try await clock.sleep(until: deadline + 0.001)
                        await self?.quiesceIfOffline(generation: current)
                    } catch { /* Path recovered or tunnel stopped. */ }
                }
            }
            return nil
        }
        offlineTask?.cancel(); offlineTask = nil
        if quiesced {
            quiesced = false
            await system.quiesceTimers(sleeping)
            if !sleeping {
                startStatsTimer()
                if let subscriptionInterval {
                    startSubscription(interval: subscriptionInterval)
                }
            }
        }
        let retry = unresolvedPath == next
        unresolvedPath = nil
        guard previous != next || retry else { return nil }
        log("Path changed: interface \(next.interfaceIndex.map(String.init) ?? "default")")
        return (generation, profile)
    }

    private func applyPathChange(_ next: ProviderPath, generation current: Generation, endpoints: [PublicKey: Endpoint]) async {
        await acquire()
        defer { release() }
        guard isActive, current == generation, path == next, let engine else { return }
        await beginReasserting(.pathChanged)
        do {
            try await engine.updateEndpoints(endpoints)
            try await engine.bumpSockets(v4: next.interfaceIndex, v6: next.interfaceIndex)
        } catch {
            await fail(error)
        }
    }

    /// Same guards as `applyPathChange`; no endpoint update and no reassert, since nothing new was learned.
    private func bumpAfterFailedResolve(_ next: ProviderPath, generation current: Generation) async {
        await acquire()
        defer { release() }
        guard isActive, current == generation, path == next, let engine else { return }
        unresolvedPath = next
        do {
            try await engine.bumpSockets(v4: next.interfaceIndex, v6: next.interfaceIndex)
        } catch {
            await fail(error)
        }
    }

    private func engineEvent(_ event: EngineEvent, generation: Generation) async {
        guard generation == self.generation, engine != nil else { return }
        if case let .engine(lifecycle) = event {
            await engineLifecycle(lifecycle, generation: generation)
        }
        if case let .handshakeCompleted(_, at) = event {
            lastHandshake = at; status.health.lastHandshake = at
            status.record(TunnelEvent(date: at, kind: .handshakeCompleted, generation: generation))
            if case .reasserting = status.phase {
                log("Reassert ended: handshake completed")
            }
            status.phase = .active(generation)
            reassertTask?.cancel(); reassertTask = nil
            await system.setReasserting(false)
        }
    }

    /// A closed device and an exhausted rebind are fatal: the engine cannot carry traffic, so the tunnel ends and on-demand
    /// restarts it. A restored configuration is only logged; the previous one is still active.
    ///
    /// ENGINE-16, documented rather than filtered: the vendored `tun_darwin.go` turns the utun interface's up/down flags
    /// into device Up/Down events outside this controller's model. Nothing here filters them; a device that ends up closed
    /// is reported as `deviceClosed` and handled below.
    private func engineLifecycle(_ event: EngineLifecycleEvent, generation current: Generation) async {
        let failure: EngineError
        switch event {
        case .deviceClosed: failure = .deviceClosed
        case .socketsBumped(ok: false): failure = .bind
        case .configRestored:
            log("Engine rejected a configuration and restored the previous one")
            return
        case .socketsBumped(ok: true): return
        }
        await acquire()
        defer { release() }
        guard current == generation, isActive else { return }
        await fail(failure)
    }

    /// Ends the tunnel after a post-start failure: tear everything down, report the failure, then ask NE to cancel,
    /// once per generation. Callers hold the lifecycle lock.
    @discardableResult
    private func fail(_ error: any Error) async -> TunnelError {
        let failure = Self.failure(error)
        let failed = generation
        connected = false
        log("Tunnel ended: \(ProviderLogText.failure(failure))")
        await cleanup()
        status.phase = .failed(failure, blockedByPolicy: false, needsSecrets: failure == .secretsUnavailable)
        if cancelledGeneration != failed {
            cancelledGeneration = failed
            await system.cancel(failure)
        }
        return failure
    }

    /// Reasserting ends with a handshake, a failure, or this timeout (WireGuard's REKEY_ATTEMPT_TIME is 90 s); the timeout
    /// returns the phase to active and leaves the stale handshake in health.
    private func beginReasserting(_ reason: ReassertReason) async {
        let deadline = clock.continuousNow + 90
        let clock = clock
        let current = generation
        status.phase = .reasserting(current, reason: reason)
        log("Reasserting: \(String(describing: reason))")
        reassertTask?.cancel()
        reassertTask = Task { [weak self] in
            do {
                try await clock.sleep(until: deadline)
                await self?.reassertTimedOut(generation: current)
            } catch { /* A handshake, failure or teardown ended the wait. */ }
        }
        await system.setReasserting(true)
    }

    private func reassertTimedOut(generation current: Generation) async {
        guard current == generation, case .reasserting = status.phase else { return }
        reassertTask = nil
        status.phase = .active(current)
        log("Reassert timed out")
        await system.setReasserting(false)
    }

    private func quiesceIfOffline(generation: Generation) async {
        guard self.generation == generation, !path.satisfied, engine != nil else { return }
        quiesced = true; statsTask?.cancel(); statsTask = nil
        log("Offline for 30 seconds: timers paused")
        subscriptionTask?.cancel(); subscriptionTask = nil
        await system.quiesceTimers(true)
    }

    private func startStatsTimer() {
        statsTask?.cancel()
        let clock = clock
        var deadline = clock.continuousNow + 30
        statsTask = Task { [weak self] in
            do {
                while !Task.isCancelled {
                    try await clock.sleep(until: deadline)
                    guard !Task.isCancelled else { break }
                    await self?.statsTick()
                    deadline = clock.continuousNow + 30
                }
            } catch { /* Teardown or sleep cancels the timer. */ }
        }
    }

    private func startSubscription(interval: TimeInterval) {
        let clock = clock
        var deadline = clock.continuousNow + interval
        subscriptionTask = Task { [weak self] in
            do {
                while !Task.isCancelled {
                    try await clock.sleep(until: deadline)
                    guard !Task.isCancelled else { break }
                    await self?.subscriptionTick()
                    deadline = clock.continuousNow + interval
                }
            } catch { /* Unsubscribe or teardown. */ }
        }
    }

    private func subscriptionTick() async {
        subscribedStats = try? await statistics()
    }

    private func statsTick() async {
        guard engine != nil, !sleeping, !quiesced else { return }
        _ = try? await statistics()
        statisticsTicks += 1
    }

    /// Every line is fixed text; nothing from a profile, a key or an endpoint is interpolated.
    func log(_ line: String) {
        logRing.append(line, at: clock.wallNow)
        logSink.write(line)
    }

    private func engineLog(_ line: EngineLogLine, generation current: Generation) {
        guard current == generation, engine != nil else { return }
        log(ProviderLogText.engine(line))
    }

    private func check(_ token: UInt64) throws {
        guard token == revision, !Task.isCancelled else { throw TunnelError.cancelled }
    }

    private func cleanup(clearingSettings: Bool = true) async {
        eventTask?.cancel(); eventTask = nil; pathTask?.cancel(); pathTask = nil; logTask?.cancel(); logTask = nil
        reassertTask?.cancel(); reassertTask = nil
        statsTask?.cancel(); statsTask = nil; offlineTask?.cancel(); offlineTask = nil
        subscriptionTask?.cancel(); subscriptionTask = nil; subscribedStats = nil; subscriptionInterval = nil
        if let engine {
            try? await engine.down(); await engine.shutdown()
        }
        engine = nil; profile = nil; lastHandshake = nil
        sleeping = false; quiesced = false; sleepInstant = nil
        path = ProviderPath(satisfied: true); unresolvedPath = nil
        let system = system
        let clock = clock
        let shield = Task {
            if clearingSettings {
                try? await withProviderDeadline(clock: clock, seconds: 10) { try await system.apply(nil) }
            }
            await system.setReasserting(false)
        }
        await shield.value
    }

    private func acquire() async {
        if busy {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            busy = true
        }
    }

    private func release() {
        if waiters.isEmpty {
            busy = false
        } else {
            waiters.removeFirst().resume()
        }
    }

    func subscribe(interval: TimeInterval) throws {
        guard interval.isFinite, (2 ... 3600).contains(interval) else { throw TunnelError.invalidConfiguration(.statisticsInterval) }
        subscriptionTask?.cancel()
        subscriptionInterval = interval
        if !sleeping, !quiesced {
            startSubscription(interval: interval)
        }
    }

    func setTransport(_ spec: TransportSpec) async throws {
        guard let engine else { throw TunnelError.backendUnavailable }
        try await engine.setTransport(spec)
    }
}
