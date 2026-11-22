// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Synchronization
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface
import WGEXPolicy

public extension TunnelController {
    /// `connectionUID` and expected generation are metadata from the authenticated XPC connection.
    /// An omitted generation means a fresh user intent, including a concurrent app/CLI request.
    /// `origin` is `.onDemand` only for the on-demand coordinator's starts (ADR-030); it keeps the console observation.
    func start(
        profileID: UUID, connectionUID: UInt32, secrets bundle: consuming SecretBundle? = nil,
        transport: TransportID? = nil, expectedGeneration: Generation? = nil, origin: IntentOrigin = .manual,
    ) async throws -> Generation {
        // Copied before the admission (no suspension): the payload crosses the command's closure; `performStart` wipes it.
        let payload = try Self.pendingSecrets(consume bundle)
        return try await withCommand(origin == .onDemand ? .onDemandStart : .start, profile: profileID, input: false) { admission in
            try await prepareStart(admission, profileID: profileID)
            return try await start(
                profileID: profileID, connectionUID: connectionUID, payload: payload, transport: transport,
                expectedGeneration: expectedGeneration, origin: origin, admission: admission,
            )
        }
    }

    @discardableResult
    func stop(
        profileID: UUID, connectionUID: UInt32, reason: StopReason = .userRequested,
        expectedGeneration: Generation? = nil,
    ) async throws -> Generation {
        try await withCommand(.stop, profile: profileID, input: false) { admission in
            try await stop(
                profileID: profileID, connectionUID: connectionUID, reason: reason,
                expectedGeneration: expectedGeneration, retainingSecrets: false, admission: admission, preemptible: true,
            )
        }
    }
}

internal extension TunnelController {
    /// The start behind the public `start`, after `prepareStart`. Nothing is held across its awaits; the registration read
    /// and a manual start's claim are one registry commit under the start's admission, and the reservation is the intent's
    /// compare-and-set (`reserve(intent:by:)`). An on-demand start passes its `ticket`, re-checked with no suspension
    /// before `reserve`.
    func start(
        profileID: UUID, connectionUID: UInt32, secrets bundle: consuming SecretBundle?, transport: TransportID?,
        expectedGeneration: Generation?, origin: IntentOrigin, admission: borrowing Admission, restarting: TunnelIntent? = nil,
        ticket: OnDemandTicket? = nil,
    ) async throws -> Generation {
        let payload = try Self.pendingSecrets(consume bundle)
        return try await start(
            profileID: profileID, connectionUID: connectionUID, payload: payload, transport: transport,
            expectedGeneration: expectedGeneration, origin: origin, admission: admission, restarting: restarting, ticket: ticket,
        )
    }

    func start(
        profileID: UUID, connectionUID: UInt32, payload: PendingDaemonSecrets?, transport: TransportID?,
        expectedGeneration: Generation?, origin: IntentOrigin, admission: borrowing Admission, restarting: TunnelIntent? = nil,
        ticket: OnDemandTicket? = nil,
    ) async throws -> Generation {
        guard acceptingRequests else { throw DaemonFailure.controllerRecoveryRequired }
        // A manual start is a newer claim: the on-demand release the profile was owed goes before it reserves.
        let record = try await registry.registrationForStart(
            profileID, connectionUID: connectionUID, claiming: origin == .manual, admission: admission,
        )
        guard acceptingRequests else { throw DaemonFailure.controllerRecoveryRequired }
        var registration = record.registration
        if let transport {
            guard let selected = registration.profile.transport.candidates.first(where: { $0.id == transport }) else {
                throw DaemonFailure.controllerInvalidConfiguration
            }
            registration.profile.transport.candidates.removeAll { $0.id == transport }
            registration.profile.transport.candidates.insert(selected, at: 0)
        }
        let prepared = registration
        try await awaitStopInFlight()
        guard acceptingRequests, !needsRecovery else { throw DaemonFailure.controllerRecoveryRequired }
        try checkExpected(expectedGeneration)
        guard intended == nil || intended?.profileID == profileID else { throw DaemonFailure.controllerAnotherTunnelActive }
        try requireCurrentStart(admission, profileID: profileID, restarting: restarting)
        if let ticket {
            try requireCurrentOnDemandAction(ticket)
        }
        let intent = TunnelIntent(profileID: profileID, ownerUID: record.ownerUID, origin: origin)
        let allocated = try reserve(intent: intent, by: admission)
        if origin == .manual || !consoleSnapshotReceived {
            loginModel = LoginSessionMonitorModel(consoleUID: record.ownerUID); consoleSnapshotReceived = true
        }
        try journal.mutate(generation: allocated) { $0.loginSuspended = false }
        let previous = operation
        previous?.cancel(); cancelBackgroundWork()
        let task = Task { [self] in
            if let previous {
                _ = await previous.result
            }
            try check(allocated)
            try await performStart(prepared, payload: payload, generation: allocated)
        }
        operation = task
        try await awaitOperation(task, generation: allocated)
        return allocated
    }
}

extension TunnelController {
    package func performStart(_ registration: DaemonProfile, payload: PendingDaemonSecrets?, generation: Generation) async throws {
        defer { payload?.wipe() }
        try await requireSecureInstall()
        do {
            // A completed older connection is drained too; an in-flight predecessor already undid itself.
            for old in journal.snapshot().resources
                where old.generation != generation
            {
                try await undo(old.generation); try check(generation)
            }
            clearPolicyFailure()
            transition(.preparing(generation), protection: snapshot.protection == .blocked ? .blocked : .unknown)
            try await checkpoint(.validateSecrets, generation: generation)
            try ProfileRegistry.validate(registration)
            let profile = registration.profile
            guard profile.transport.candidates.allSatisfy({ $0.spec == .udp }) else { throw DaemonFailure.controllerInvalidConfiguration }
            snapshot.transport = profile.transport.candidates.first?.id
            try await ports.policy.configureProfile(profile)
            policyProfileID = profile.id
            exclusionState = ExclusionResolutionState(
                profileID: profile.id, literal: profile.exclusions.effectiveRanges(), ports: profile.exclusions.ports,
            )
            let bundle = try await obtainSecrets(payload, registration: registration)
            let parsed = try Self.pack(bundle, profile: profile)
            try check(generation)
            try updateResource(GenerationResources(generation: generation), generation: generation)
            try entry(.validateSecrets, .didApply, generation: generation)

            try await prepareEndpoints(profile, generation: generation)
            let created = try await startEngine(profile, parsed: parsed, generation: generation)

            try await configureNetwork(profile, identity: created.identity, engine: created.engine, generation: generation)
            try await verifyAndCommit(created, generation: generation)
        } catch {
            throw await failStart(error, generation: generation)
        }
    }

    /// Undoes a failed start and publishes the failed phase; returns the error to rethrow.
    package func failStart(
        _ failure: any Error, generation: Generation, cleanupGeneration: Generation? = nil,
        retiredEngine: any EngineControlling? = nil,
    ) async -> any Error {
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.log(failure, context: "start")
            if let last = journal.snapshot().entries.last(where: { $0.generation == generation }), last.action == .willApply {
                DaemonDiagnostics.stepFailed(.start, step: last.step)
            }
        #endif
        guard !abandonedGenerations.contains(generation) else {
            await retiredEngine?.shutdown()
            return DaemonFailure.controllerOperationFailed
        }
        let failedNote = snapshot.protectionNote
        let cleanup = cleanupGeneration ?? generation
        let engineFailure: TunnelError? = if (failure as? EngineError) == .deviceClosed {
            .engine(code: -9)
        } else if let tunnel = failure as? TunnelError, case .engine = tunnel {
            tunnel
        } else {
            nil
        }
        // A fatal handle must never receive down/configuration while the existing rollback path drains resources.
        let retired = retiredEngine ?? (engineFailure == nil ? nil : engines.removeValue(forKey: cleanup))
        do {
            if engineFailure != nil {
                try journal.mutate(generation: generation) { $0.captiveWindow = nil }
            }
            try await undo(cleanup)
        } catch {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.log(error, context: "undo after failed start")
            #endif
            await retired?.shutdown()
            if generation == self.generation {
                transition(
                    .failed(engineFailure ?? .backendUnavailable, blockedByPolicy: false, needsSecrets: false),
                    protection: .unknown,
                )
            }
            return DaemonFailure.controllerOperationFailed
        }
        await retired?.shutdown()
        if generation == self.generation, failedNote == .verificationFailed || failedNote == .canaryFailed {
            snapshot.protectionNote = failedNote
        }
        await publishStartFailure(failure, engineFailure: engineFailure, generation: generation)
        return failure
    }

    private func publishStartFailure(_ failure: any Error, engineFailure: TunnelError?, generation: Generation) async {
        if generation == self.generation {
            let missing = (failure as? DaemonFailure) == .controllerSecretsUnavailable
            if snapshot.protectionNote != .ipv6Unavailable, (failure as? DaemonFailure)?.kind == .pfCanaryFailed {
                snapshot.protectionNote = .canaryFailed
            }
            let blocking = intended != nil || settings.lockdown
            let verified = if engineFailure != nil {
                await ports.policy.verification() == .blocked
            } else {
                true
            }
            guard generation == self.generation else { return }
            transition(
                .failed(
                    engineFailure ?? (missing ? .secretsUnavailable : .backendUnavailable),
                    blockedByPolicy: blocking && (engineFailure == nil || verified),
                    needsSecrets: missing,
                ),
                protection: blocking ? (engineFailure == nil || verified ? .blocked : .unknown) : .unprotected,
            )
        }
    }

    private func prepareEndpoints(_ profile: TunnelProfile, generation: Generation) async throws {
        try await checkpoint(.blocking, generation: generation)
        try await acquireToken(generation)
        try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: []), generation: generation)
        try entry(.blocking, .didApply, generation: generation)

        try await checkpoint(.resolve, generation: generation)
        do { rotation.candidates = try await resolve(profile, generation: generation) }
        catch is CancellationError { throw CancellationError() }
        catch { throw DaemonFailure.startup(.resolverUnavailable) }
        rotation.indices = rotation.candidates.mapValues { _ in 0 }; rotation.handshakePeers = []; rotation.backoffSeconds = 5
        try check(generation)
        // Excluded host names resolve on the physical resolvers before tunnel DNS applies; a failure only warns (DEC-087).
        try await resolveExclusions(profile, generation: generation)
        try entry(.resolve, .didApply, generation: generation)

        try await checkpoint(.allowEndpoints, generation: generation)
        try await applyPolicy(.connecting(resolvers: underlay.resolvers, endpoints: endpointAddresses), generation: generation)
        try entry(.allowEndpoints, .didApply, generation: generation)
    }

    private func startEngine(
        _ profile: TunnelProfile,
        parsed: borrowing ParsedSecrets,
        generation: Generation,
    ) async throws -> CreatedDaemonEngine {
        transition(.configuring(generation), protection: .blocked)
        try await checkpoint(.createEngine, generation: generation)
        // Off the actor: wgex_create and the utun it makes can block for as long as the host is slow. On return the
        // abandoned set and the generation are re-checked (here and by `check` below) before the engine is adopted.
        let engineConfiguration = EngineConfiguration(
            tun: .createUTun(mtu: Int32(profile.interface.mtu ?? 1280)),
            bindInterfaceIndexV4: underlay.socketV4, bindInterfaceIndexV6: underlay.socketV6,
        )
        let created = try await offActor(.createEngine) {
            try await OffActor.createEngine(ports.engineFactory, configuration: engineConfiguration, generation: generation)
        }
        if abandonedGenerations.contains(generation) {
            await created.engine.shutdown()
            throw DaemonFailure.journalStaleGeneration
        }
        engines[generation] = created.engine
        observeEvents(created.engine, generation: generation, profileID: profile.id)
        // A late return is retained for rollback even after a new generation was reserved.
        try journal.mutate(generation: nil) { document in
            var resource = document.resources.first { $0.generation == generation } ?? GenerationResources(generation: generation)
            resource.identity = created.identity
            document.resources.removeAll { $0.generation == generation }; document.resources.append(resource)
        }
        try check(generation)
        try entry(.createEngine, .didApply, generation: generation)

        try await checkpoint(.configureEngine, generation: generation)
        var configured = profile
        for index in configured.peers.indices where rotation.candidates[configured.peers[index].publicKey] == nil {
            configured.peers[index].endpoint = nil
        }
        let configuration = try UAPIEncoder.fullConfiguration(configured, secrets: parsed, endpoints: selectedEndpoints)
        try await created.engine.setConfiguration(configuration)
        try check(generation); try entry(.configureEngine, .didApply, generation: generation)
        try await checkpoint(.engineUp, generation: generation)
        try await created.engine.up()
        try check(generation); try entry(.engineUp, .didApply, generation: generation)

        return created
    }

    private func verifyAndCommit(_ created: CreatedDaemonEngine, generation: Generation) async throws {
        try await checkpoint(.verify, generation: generation)
        try await verifyNetwork(ProtectionExpectation(
            resources: resource(generation), policy: journal.snapshot().pfPolicy, engine: created.engine,
        ))
        try check(generation); try entry(.verify, .didApply, generation: generation)
        try await checkpoint(.connected, generation: generation)
        try await applyPolicy(.connected(interfaceName: created.identity.name, endpoints: endpointAddresses), generation: generation)
        try await verifyNetwork(ProtectionExpectation(
            resources: resource(generation), policy: journal.snapshot().pfPolicy, engine: created.engine,
        ))
        try check(generation); try entry(.connected, .didApply, generation: generation)
        try await checkpoint(.killStates, generation: generation)
        // Policy apply owns transition-scoped kills; retain the established journal checkpoint.
        try check(generation); try entry(.killStates, .didApply, generation: generation)
        try await checkpoint(.commit, generation: generation)
        try entry(.commit, .didApply, generation: generation)
        health = .init(clock: ControllerHealthClock(clock: clock))
        transition(.active(generation), protection: .protected)
        rotation.attemptStarted = clock.now
    }

    /// A supplied bundle is used for this start and published only while its registration is still current (`publishBundle`).
    private func obtainSecrets(_ payload: PendingDaemonSecrets?, registration: DaemonProfile) async throws -> SecretBundle {
        let profile = registration.profile
        if let payload {
            let bundle = try SecretsWireLayout.decode(payload.copy())
            _ = try Self.pack(bundle, profile: profile) // Check key identity and reference completeness before publication.
            _ = try await publishBundle(payload, for: registration)
            return bundle
        }
        do { return try await SecretsWireLayout.decode(secrets.loadBundle(profileID: profile.id)) }
        catch { throw DaemonFailure.controllerSecretsUnavailable }
    }

    package static func pack(_ bundle: borrowing SecretBundle, profile: TunnelProfile) throws -> ParsedSecrets {
        let privateKey = try PrivateKey(bytes: bundle.privateKey())
        guard try privateKey.publicKey() == profile.interface.publicKey,
              Set(bundle.presharedKeyPeers) == Set(profile.secrets.presharedKeys.keys),
              Set(bundle.carrierIDs) == Set(profile.secrets.carrierCredentials.keys)
        else { throw DaemonFailure.controllerInvalidConfiguration }
        var packed = try SecretBytes(zeroedCount: 32 * (1 + profile.secrets.presharedKeys.count))
        var references: [SecretRef: Range<Int>] = [profile.secrets.privateKey: 0 ..< 32]
        try bundle.privateKey().copyBytes(into: &packed, at: 0)
        var offset = 32
        for (peer, reference) in profile.secrets.presharedKeys.sorted(by: { $0.key.base64 < $1.key.base64 }) {
            guard let key = try bundle.presharedKey(for: peer) else { throw DaemonFailure.controllerInvalidConfiguration }
            try key.copyBytes(into: &packed, at: offset)
            references[reference] = offset ..< offset + 32; offset += 32
        }
        return try ParsedSecrets(bytes: packed, references: references)
    }

    private func configureNetwork(
        _ profile: TunnelProfile, identity: TunnelIdentity, engine: any EngineControlling, generation: Generation,
    ) async throws {
        try await checkpoint(.configureInterface, generation: generation)
        let tunnelRoutes = Self.routes(profile, interfaceName: identity.name, excluding: exclusionRanges(for: profile))
        var resources = resource(generation); resources.addresses = try Self.tunnelAddresses(profile, routes: tunnelRoutes)
        try updateResource(resources, generation: generation)
        try await configureOffActor(
            identity: identity, addresses: resources.addresses,
            mtu: UnderlayMonitorModel.mtu(override: profile.interface.mtu, underlay: underlayMTU, carrier: false),
            generation: generation,
        )
        // The actor was released during the ioctls: a superseded or abandoned generation goes no further.
        try check(generation)
        try await confirmOwnTunnel(identity, engine: engine, generation: generation)
        try check(generation); try entry(.configureInterface, .didApply, generation: generation)

        try await checkpoint(.installRoutes, generation: generation)
        resources.canaryRoute = try await ports.routes.canaryRoute(underlay: underlay)?.withPortRoutes(Self.needsPortRoutes(profile))
        // The scoped canary route goes in before the tunnel's routes: a later route failure must never leave the /1
        // routes without it, because the bound evaluation probe then has no route and blocking cannot be measured
        // (M1-19 D14, D15). The scoped halves for listed ports (DEC-126) follow it.
        resources.routes = (resources.canaryRoute?.routes ?? []) + tunnelRoutes
        try updateResource(resources, generation: generation)
        try await ports.routes.install(resources.routes, generation: generation)
        try check(generation); try entry(.installRoutes, .didApply, generation: generation)

        try await checkpoint(.installDNS, generation: generation)
        if let dns = networkDNS(profile) {
            resources.dns = dns; resources.dnsKey = DNSConfigurator.key(profileID: profile.id)
            try updateResource(resources, generation: generation)
            try await ports.dns.apply(dns, generation: generation)
        }
        try check(generation); try entry(.installDNS, .didApply, generation: generation)
    }

    /// A profile that lists local ports (DEC-126) gets the scoped /1 halves on the physical interface, so an app bound to
    /// it has a route there under the tunnel's routes (M08-T12); the packet filter passes only the listed ports.
    package static func needsPortRoutes(_ profile: TunnelProfile) -> Bool {
        !profile.exclusions.ports.isEmpty
    }

    /// The IPv6 host address a utun carries when its profile routes IPv6 but has no IPv6 address: the same unique-local
    /// address the Network Extension backend assigns (NESettingsGenerator).
    package static let ipv6RouteAddress = "fdf0:7765:7800::1/128"

    /// The profile's addresses, plus `ipv6RouteAddress` when IPv6 routes would otherwise reach a utun without an IPv6
    /// address. XNU answers RTM_ADD with ENETUNREACH when the AF_LINK gateway's interface has no address of the
    /// destination's family, which is what a v4-only full tunnel's blockOutside ::/1 and 8000::/1 hit (M1-19 D14).
    package static func tunnelAddresses(_ profile: TunnelProfile, routes: [RouteSpec]) throws -> [IPAddressRange] {
        let addresses = profile.interface.addresses
        guard routes.contains(where: { $0.destination.contains(":") }), !addresses.contains(where: \.isIPv6) else { return addresses }
        return try addresses + [IPAddressRange(ipv6RouteAddress)]
    }

    package func configureChangedUnderlay(_ profile: TunnelProfile, identity: TunnelIdentity) async throws {
        // The maintenance epoch is taken before the first await, so every resumption below is fenced against it.
        let epoch = generation
        // The tunnel transports both families even when its physical endpoint uses only IPv4.
        var resources = resource(epoch)
        if journal.snapshot().captiveWindow == nil {
            let next = try await ports.routes.canaryRoute(underlay: underlay)?.withPortRoutes(Self.needsPortRoutes(profile))
            try check(epoch)
            if next != resources.canaryRoute {
                try await ports.routes.removeCanaryRoute(of: epoch)
                try check(epoch)
                if let old = resources.canaryRoute {
                    resources.routes.removeAll(where: old.routes.contains)
                }
                resources.routes += next?.routes ?? []
                resources.canaryRoute = next
                try updateResource(resources, generation: epoch)
                try await ports.routes.install(next?.routes ?? [], generation: epoch)
                try check(epoch)
            }
        }
        try await configureOffActor(
            identity: identity, addresses: resources.addresses,
            mtu: UnderlayMonitorModel.mtu(override: profile.interface.mtu, underlay: underlayMTU, carrier: false), generation: epoch,
        )
        try check(epoch)
        try await confirmOwnTunnel(identity, engine: engines[epoch], generation: epoch)
        if let dns = resources.dns, journal.snapshot().captiveWindow == nil {
            try await ports.dns.apply(dns, generation: epoch)
            try check(epoch)
        }
    }

    /// The interface configure, off the actor (see `OffActor`); the caller re-checks its generation on return.
    private func configureOffActor(
        identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16, generation: Generation,
    ) async throws {
        try await offActor(.configure) {
            try await OffActor.configure(ports.device, identity: identity, addresses: addresses, mtu: mtu, generation: generation)
        }
    }

    private func networkDNS(_ profile: TunnelProfile) -> DNSConfiguration? {
        let servers = profile.interface.dns
        guard profile.protection.dnsPolicy != .systemDefault, !servers.isEmpty else { return nil }
        let domains: [String] = switch profile.protection.dnsPolicy {
        case let .split(values): values
        case .tunnelAll: [""]
        case .systemDefault: []
        }
        return DNSConfiguration(
            servers: servers.map(\.stringRepresentation),
            searchDomains: profile.interface.searchDomains,
            matchDomains: domains,
        )
    }
}

package extension TunnelController {
    func performStop(profileID: UUID, reason: StopReason, explicit: Bool, generation: Generation) async throws {
        try check(generation)
        stoppingProfile = (profileID, generation)
        defer {
            if stoppingProfile?.generation == generation {
                stoppingProfile = nil
            }
        }
        var failed = false
        do { try withdrawCaptiveException() } catch { failed = true }
        transition(.stopping(generation, reason: reason), protection: .unknown)
        failed = await stopStep(.stopBlocking, generation: generation) {
            try await self.acquireToken(generation)
            let measured = try await self.applyStopBlocking(generation)
            self.transition(.stopping(generation, reason: reason), protection: measured ? .blocked : .unknown)
        } || failed
        failed = await stopResources(generation) || failed
        failed = await finishStop(profileID: profileID, explicit: explicit, generation: generation) || failed
        try check(generation)
        maintenanceState.retryAt = nil; maintenanceState.retryAttempt = 0
        if failed {
            pendingTeardownProfileID = profileID
            snapshot.recoveryFailureReason = .reconciliationFailed
            transition(.failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false), protection: .unknown)
            throw DaemonFailure.controllerOperationFailed
        }
        pendingTeardownProfileID = nil
        needsRecovery = false; snapshot.recoveryFailureReason = nil; clearPolicyFailure()
        transition(.idle, protection: failurePolicy == .disconnected ? .unprotected : .blocked)
    }

    /// Loads the teardown's blocking policy. A canary failure leaves those rules loaded but unmeasured: after a failed
    /// full-tunnel start the tunnel's /1 routes can remain without the scoped canary route, so the bound probe has no
    /// route (M1-19 D15). Teardown then continues and the measured final policy decides the stop's result.
    private func applyStopBlocking(_ generation: Generation) async throws -> Bool {
        do {
            try await applyPolicy(settings.lockdown ? .lockdown : (intended != nil ? .error : .disconnecting), generation: generation)
            return true
        } catch let failure as DaemonFailure where failure.kind == .pfCanaryFailed {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.stepFailed(.stop, step: .stopBlocking)
            #endif
            return false
        }
    }

    private func stopStep(_ step: DaemonStep, generation: Generation, action: () async throws -> Void) async -> Bool {
        guard generation == self.generation else { return true }
        var failed = false
        do { try await checkpoint(step, generation: generation) } catch { failed = true }
        guard generation == self.generation else { return true }
        // A journal/checkpoint error must not skip the actual teardown action.
        do { try await action(); try check(generation); try entry(step, .didApply, generation: generation) }
        catch { failed = true }
        return failed
    }

    private func stopResources(_ generation: Generation) async -> Bool {
        var failed = await removeStopNetworking(generation)
        let retired = engines
        failed = await stopStep(.engineDown, generation: generation) {
            var error: any Error?
            for engine in retired.values {
                do { try await engine.down() } catch EngineError.deviceClosed { /* Already down. */ }
                catch let cause { error = cause }
            }
            if let error {
                throw error
            }
        } || failed
        failed = await stopStep(.engineShutdown, generation: generation) {
            for engine in retired.values {
                await engine.shutdown()
            }
            for key in retired.keys {
                self.engines.removeValue(forKey: key)
            }
        } || failed
        if !failed {
            do { try journal.mutate(generation: generation) { $0.resources = [] } } catch { failed = true }
        }
        return failed
    }

    private func removeStopNetworking(_ generation: Generation) async -> Bool {
        let resources = journal.snapshot().resources
        var failed = await stopStep(.removeDNS, generation: generation) {
            var error: any Error?
            for resource in resources {
                do { try await self.ports.dns.remove(generation: resource.generation) } catch let cause { error = cause }
            }
            if let error {
                throw error
            }
        }
        failed = await stopStep(.removeRoutes, generation: generation) {
            var error: any Error?
            for resource in resources {
                do { try await self.ports.routes.removeRoutes(of: resource.generation) } catch let cause { error = cause }
            }
            if let error {
                throw error
            }
        } || failed
        return failed
    }

    private func finishStop(profileID: UUID, explicit: Bool, generation: Generation) async -> Bool {
        let final = failurePolicy
        var failed = await stopStep(.finalPolicy, generation: generation) {
            try await self.applyPolicy(final, generation: generation)
        }
        failed = await stopStep(.releaseToken, generation: generation) {
            if final == .disconnected, let token = self.journal.snapshot().pfToken {
                try await self.ports.policy.releaseToken(token)
                try self.journal.mutate(generation: generation) { $0.pfToken = nil; $0.pfBootSession = nil; $0.pfTokenPID = nil }
            }
        } || failed
        // Section 7.4 forbids state kills on disconnect. Preserve the replay checkpoint only.
        failed = await stopStep(.stopKillStates, generation: generation) {} || failed
        failed = await stopStep(.deleteSecrets, generation: generation) {
            if explicit {
                try await self.deletePendingSecrets(profileID, generation: generation)
            }
        } || failed
        rotation.candidates = [:]; rotation.hosts = [:]; rotation.indices = [:]; rotation.handshakePeers = []; rotation.attemptStarted = nil
        return failed
    }
}
