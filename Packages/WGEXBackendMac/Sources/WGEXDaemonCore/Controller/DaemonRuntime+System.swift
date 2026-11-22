// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
#if os(macOS)
    import Darwin
    import Dispatch
    import Foundation
    import Synchronization
    import WGEXCore
    import WGEXDaemonProtocol

    /// Raw sections are collected only on export, then redacted by the injected diagnostics adapter.
    public struct DaemonSystemSnapshot: Sendable {
        /// Fixed PF command result, validated before export.
        public let pf: PFCommandResult
        /// Encoded owned-route metadata.
        public let routes: Data
        /// Resolver ordering, redacted before export.
        public let dns: String
    }

    internal extension DaemonSystemSnapshot {
        /// PF is the admission check: unavailable PF never triggers route or resolver inspection.
        static func collect(
            packetFilter: @Sendable () async throws -> PFCommandResult,
            routes: @Sendable () async throws -> Data, dns: @Sendable () async throws -> String,
        ) async throws -> Self {
            let pf = try await packetFilter()
            guard pf.status == 0, pf.stdout.utf8.count <= 1 << 20 else {
                return Self(pf: pf, routes: Data(), dns: "")
            }
            let routeData = try await routes()
            return try await Self(pf: pf, routes: routeData, dns: dns())
        }
    }

    public extension DaemonRuntime {
        /// Creates the redactor at the executable boundary without a backend-to-diagnostics dependency.
        typealias DiagnosticsFactory = @Sendable (@escaping @Sendable () async throws -> DaemonSystemSnapshot)
            -> any DaemonDiagnosticsProviding

        /// Production wiring runs only when explicitly invoked by the guarded executable.
        static func runSystem(
            daemonVersion: String, daemonBuild: Int, engineFactory: any DaemonEngineCreating,
            makeDiagnostics: DiagnosticsFactory,
            log: @escaping @Sendable (DaemonRuntimeMessage) -> Void,
            failure: @escaping @Sendable (any Error, StaticString) -> Void,
        ) async throws {
            do { try AdminRightPolicy.system.install() }
            catch { log(.adminRightDefinitionFailed) }
            let storage = try SystemRuntimeStorage(build: daemonBuild, log: log)
            let network = try SystemRuntimeNetwork(journal: storage.journal, log: log)
            let backend = try makeBackend(
                storage: storage,
                network: network,
                engineFactory: engineFactory,
                makeDiagnostics: makeDiagnostics,
            )
            let composition = try DaemonComposition(
                controller: backend.controller, daemonVersion: daemonVersion, daemonBuild: daemonBuild,
                minimumClientBuild: 0, minimumDaemonBuild: Int(storage.floor.read()), authorisation: .system,
            )
            let runtime = DaemonRuntime()
            let monitors = makeMonitors(controller: backend.controller, journal: storage.journal, runtime: runtime, log: log)
            await serve(runtime: runtime, composition: composition, backend: backend, monitors: monitors, log: log, failure: failure)
        }
    }

    private struct SystemRuntimeStorage: Sendable {
        let directory: StateDirectory
        let floor: MinimumBuildFloor
        let journal: DaemonJournal
        let keyProvider: any DaemonKeyProvisioning

        init(build: Int, log: @Sendable (DaemonRuntimeMessage) -> Void) throws {
            directory = try StateDirectory(root: URL(fileURLWithPath: "/Library/Application Support/WGEX"), ownerUID: 0)
            try SystemStateAdapters.excludeFromTimeMachine(directory)
            floor = MinimumBuildFloor(directory: directory)
            try floor.admit(build: UInt64(build))
            journal = try DaemonJournal(directory: directory)
            keyProvider = SystemDaemonKeyProvider()
            do { _ = try keyProvider.wrappingKey() }
            catch { log(.wrappingKeyUnavailable) }
        }
    }

    private struct SystemRuntimeNetwork: Sendable {
        let runner: PFCtl
        let policy: PolicyLivenessAdapter
        let identities: SystemInterfaceIdentity
        let routes: RouteTable
        let dns: DNSConfigurator

        init(journal: DaemonJournal, log: @escaping @Sendable (DaemonRuntimeMessage) -> Void) throws {
            runner = PFCtl(system: SystemPacketFilterSystem())
            let initialContext = try PFContext(underlay: PFInterface("lo0"), consoleUID: 0)
            #if WGEX_LAB_BUILD
                var context = initialContext
                context.labEscapeHatch = try PFAddress("192.168.64.1")
            #else
                let context = initialContext
            #endif
            let enforcer = try PolicyEnforcer(
                runner: runner, journal: DaemonPFTokenJournal(journal: journal), context: context,
                canaryProbe: { try SystemCanaryProbe.send() },
                onExternalRelease: { log(.externalReferenceReleased) },
            )
            policy = PolicyLivenessAdapter(policy: enforcer, runner: runner)
            identities = SystemInterfaceIdentity()
            routes = RouteTable(journal: journal, kernel: SystemRouteSocket(), identities: identities, pid: getpid())
            dns = DNSConfigurator(journal: journal, session: SystemDNSSession())
        }

        func snapshot() async throws -> DaemonSystemSnapshot {
            try await DaemonSystemSnapshot.collect(packetFilter: {
                try await runner.system.run(arguments: ["-a", PacketFilterRenderer.anchor, "-sr"], input: Data(), deadline: 10)
            }, routes: { try await JSONEncoder().encode(routes.ownedRoutes()) }, dns: { try await SystemDNSSession().resolverListing() })
        }

        func ports(engineFactory: any DaemonEngineCreating, journal: DaemonJournal) -> DaemonPorts {
            DaemonPorts(
                engineFactory: engineFactory, routes: routes, dns: dns, policy: policy,
                resolver: UnderlayResolver(engine: IsolatedUnderlayResolver()),
                device: SystemTunnelDevice(identities: identities, journal: journal),
                verifier: NetworkProtectionVerifier(routes: routes, dns: dns, identities: identities, policy: policy),
                reality: NetworkRealityInspector(routes: routes, dns: dns, identities: identities),
            )
        }
    }

    private struct SystemRuntimeBackend: Sendable {
        let controller: TunnelController
        let registry: ProfileRegistry
        let diagnostics: any DaemonDiagnosticsProviding
    }

    private func makeBackend(
        storage: SystemRuntimeStorage, network: SystemRuntimeNetwork, engineFactory: any DaemonEngineCreating,
        makeDiagnostics: DaemonRuntime.DiagnosticsFactory,
    ) throws -> SystemRuntimeBackend {
        let diagnostics = makeDiagnostics { try await network.snapshot() }
        let store = try DaemonSecretStore(
            directory: storage.directory, keyProvider: storage.keyProvider,
            observeBundle: { try diagnostics.registerSecretWire($0) },
        )
        let registry = try ProfileRegistry(
            repository: DirectoryProfileRepository(directory: storage.directory), secrets: store, bundles: store,
            profileRegistered: { diagnostics.register($0) },
        )
        diagnostics.setPreparation(registry.diagnosticsPreparation(unavailable: diagnostics.sectionUnavailableFailure()))
        let secureInstall: any SecureInstallChecking
        do {
            secureInstall = try SecureInstall(
                system: SystemSecureInstall(), provisionKey: { try storage.keyProvider.provision() },
                validateKey: { _ = try storage.keyProvider.wrappingKey() },
            )
        } catch { secureInstall = UnavailableSecureInstall() }
        let controller = TunnelController(
            registry: registry, secureInstall: secureInstall, journal: storage.journal, secrets: store,
            ports: network.ports(engineFactory: engineFactory, journal: storage.journal),
            underlay: UnderlaySnapshot(v4: nil, v6: nil, resolvers: [], interfaceNames: []), diagnostics: diagnostics, underlayMTU: 1500,
            interfaces: SystemInterfaceClassifier(),
        )
        return SystemRuntimeBackend(controller: controller, registry: registry, diagnostics: diagnostics)
    }

    /// Internal so host tests can inspect the composition without starting any system adapter.
    internal func makeMonitors(
        controller: TunnelController, journal: DaemonJournal, runtime: DaemonRuntime,
        log: @escaping @Sendable (DaemonRuntimeMessage) -> Void,
    ) -> DaemonNetworkMonitoring {
        #if WGEX_LAB_BUILD
            // M1-47: Lab only, and inert unless LabGuard.isLabHost(); SIGUSR1 and SIGUSR2 inject a sleep and a wake.
            let power: any PowerMonitoring = LabPowerInjector(inner: SystemPowerMonitor())
        #else
            let power: any PowerMonitoring = SystemPowerMonitor()
        #endif
        return DaemonNetworkMonitoring(
            controller: controller, routes: SystemRouteMonitor(),
            underlay: SystemUnderlayMonitor(ownedDNSKeys: { Set(journal.snapshot().resources.compactMap(\.dnsKey)) }),
            power: power, login: SystemLoginSessionMonitor(), ownPID: getpid(),
            readUnderlay: { try SystemUnderlayMonitor.read() }, failure: { log(.networkUnknown) },
            recoveryUnderlay: { event in
                guard await runtime.isRecovering else { return false }
                await controller.updateStartupUnderlay(event); await runtime.retryNow(); return true
            },
        )
    }

    private func serve(
        runtime: DaemonRuntime, composition: DaemonComposition, backend: SystemRuntimeBackend, monitors: DaemonNetworkMonitoring,
        log: @escaping @Sendable (DaemonRuntimeMessage) -> Void, failure: @escaping @Sendable (any Error, StaticString) -> Void,
    ) async {
        let controller = backend.controller
        let listener = NSXPCDaemonListener(daemon: composition.dispatcher, afterUpdateReply: { exit(0) })
        let refresh: @Sendable () async -> Void = {
            if let event = try? SystemUnderlayMonitor.read() {
                await controller.updateStartupUnderlay(event)
            }
        }
        let termination = terminationSource(runtime: runtime, refresh: refresh, log: log)
        termination.source.resume(); termination.interruptSource.resume()
        defer { termination.source.cancel(); termination.interruptSource.cancel() }
        if controller.previousShutdownWasClean {
            log(.previousShutdownClean)
        } else {
            log(.previousShutdownUnrecorded)
        }
        await runtime.serveUntilTermination(events: termination.events, startup: {
            await composition.run(
                runtime: runtime, startListener: { startListener(listener, backend: backend, log: log) },
                startMonitors: { try await monitors.start() }, refreshUnderlay: refresh,
            )
        }, mainLoop: {
            await runtime.runMainLoop(ports: .init(
                retryLifecycle: { await monitors.retryPending() }, tick: { try await controller.tick() },
                failure: { error in log(.verificationUnknown); failure(error, "tick") },
            ))
        })
    }

    private func startListener(
        _ listener: NSXPCDaemonListener,
        backend: SystemRuntimeBackend,
        log: @escaping @Sendable (DaemonRuntimeMessage) -> Void,
    ) {
        #if WGEX_LAB_BUILD
            // DEC-013: publish this daemon's own code-directory hashes before any Lab client can connect.
            do { try LabDaemonIdentityFile.production.publish(LabRunningCode().runningCdhashes()) }
            catch { log(.labIdentityUnpublished) }
        #endif
        listener.start(); log(.listeningRecovering)
        Task {
            do { try await backend.registry.registerInstalledProfiles() }
            catch { backend.diagnostics.disableExports(); log(.diagnosticRegistrationPending) }
        }
    }

    internal nonisolated func terminationSource(
        runtime: DaemonRuntime, refresh: @escaping @Sendable () async -> Void, log: @escaping @Sendable (DaemonRuntimeMessage) -> Void,
    ) -> (source: any DispatchSourceSignal, interruptSource: any DispatchSourceSignal, events: AsyncStream<Void>) {
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interruptSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        let events = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let begun = Mutex(false)
        let handler: @Sendable () -> Void = {
            guard begun.withLock({ value in
                if value {
                    return false
                }; value = true; return true
            }) else { return }
            Task {
                await runtime.terminate(refreshUnderlay: refresh, waiting: { log(.shutdownWaiting) })
                log(.shutdownComplete)
                events.continuation.yield(()); events.continuation.finish()
            }
        }
        source.setEventHandler(handler: handler)
        interruptSource.setEventHandler(handler: handler)
        return (source, interruptSource, events.stream)
    }
#endif
