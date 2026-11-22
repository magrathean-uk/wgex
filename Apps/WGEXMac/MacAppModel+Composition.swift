// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
#if os(macOS)
    import AppKit
    import Foundation
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXUI
    #if DEBUG || WGEX_LAB_BUILD
        import WGEXTesting
    #endif

    public extension MacAppModel {
        #if DEBUG || WGEX_LAB_BUILD
            /// Composes guarded real adapters or an explicitly selected Debug/Lab preview.
            convenience init(
                arguments: [String] = ProcessInfo.processInfo.arguments,
                container: URL? = nil,
                fakeServiceFactory: () -> FakeServiceController = { FakeServiceController() },
                realServiceFactory: () -> any ServiceControlling = { ServiceController() },
                preferencesLoader: (() async throws -> MacPreferences)? = nil,
                systemOperationsPermitted: () -> Bool = {
                    ServiceController.systemOperationsPermitted(isDebugBuild: ServiceController.isDebugBuild, sysctl: SystemSysctl())
                },
                applyDockPolicy: @escaping (Bool) -> Void = { NSApplication.shared.setActivationPolicy($0 ? .accessory : .regular) },
            ) {
                let simulated = arguments.contains("-WGEXFakeBackend")
                let root = MacAppComposition.storageRoot(container: container, simulated: simulated)
                let composition = simulated
                    ? MacAppComposition.preview(root: root, serviceFactory: fakeServiceFactory)
                    : MacAppComposition.real(root: root, serviceFactory: realServiceFactory, permitted: systemOperationsPermitted())
                self.init(composition: composition, preferencesLoader: preferencesLoader, applyDockPolicy: applyDockPolicy)
            }
        #else
            /// Release always composes the real daemon client and Keychain store.
            convenience init(
                arguments _: [String] = ProcessInfo.processInfo.arguments,
                container: URL? = nil,
                realServiceFactory: () -> any ServiceControlling = { ServiceController() },
                preferencesLoader: (() async throws -> MacPreferences)? = nil,
                applyDockPolicy: @escaping (Bool) -> Void = { NSApplication.shared.setActivationPolicy($0 ? .accessory : .regular) },
            ) {
                let root = MacAppComposition.storageRoot(container: container, simulated: false)
                let composition = MacAppComposition.real(root: root, serviceFactory: realServiceFactory, permitted: true)
                self.init(composition: composition, preferencesLoader: preferencesLoader, applyDockPolicy: applyDockPolicy)
            }
        #endif
    }

    @MainActor
    internal struct MacAppComposition {
        internal let persistence: MacPersistence
        /// Shared by editor, import, export and daemon secret handoff; never a separate app-only store.
        internal let secretStore: any SecretStore
        internal let daemon: MacDaemonComposition?
        internal let shell: MacShellModel
        internal let repository: MacProfileRepository
        /// Relays the Wi-Fi network name for on-demand rules; nil for previews, which have no daemon.
        internal var onDemandRelay: MacOnDemandRelay?
        #if DEBUG || WGEX_LAB_BUILD
            internal var fakeService: FakeServiceController?
        #endif

        internal static func storageRoot(container: URL?, simulated: Bool) -> URL {
            container ?? URL.applicationSupportDirectory.appendingPathComponent(
                simulated ? "WGEX/Simulation" : "WGEX", isDirectory: true,
            )
        }

        internal static func real(root: URL, serviceFactory: () -> any ServiceControlling, permitted: Bool) -> MacAppComposition {
            let persistence = MacPersistence(container: root, simulated: false)
            let secretStore = makeSecretStore(simulated: false, root: root)
            let daemon = MacDaemonComposition(
                transport: NSXPCClientTransport(),
                clientVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1",
                clientBuild: Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1") ?? 1,
                secretStore: secretStore, systemOperationsPermitted: permitted,
                authorizeSecureInstall: { try await SystemSecureInstallAuthorisation.grant() },
            )
            let access = makeProfileAccess(permitted: permitted, daemon: { daemon })
            let repository = makeRepository(root: root, persistence: persistence, secretStore: secretStore, access: access)
            let relay = makeOnDemandRelay(daemon)
            let service = serviceFactory()
            let uninstall = MacUninstallComposition.steps(
                client: daemon.client, permitted: permitted,
                authorize: { try await SystemSecureInstallAuthorisation.grant() },
                daemonService: service as? ServiceController ?? ServiceController(),
                loginItem: ServiceController(operations: .mainAppLoginItem()),
                repository: repository, persistence: persistence,
                removeKeychainItems: MacUninstallComposition.keychainRemoval(secretStore),
                removePreferences: MacUninstallComposition.removeDefaults,
                quit: { MacUninstallComposition.terminateAfterSheets() },
            )
            let dependencies = MacShellDependencies(
                backend: daemon.client, service: service, simulated: false, hostGuarded: !permitted,
                operations: daemonOperations(
                    daemon,
                    persistence: persistence,
                    repository: repository,
                    relay: relay,
                    uninstall: uninstall,
                    reportError: { access.reportError($0) },
                ),
            )
            let shell = MacShellModel(dependencies: dependencies)
            configureProfileAccess(access, shell: shell)
            relay.armedWithSSIDList = { [weak shell] in
                guard let shell, let armed = shell.armedProfile else { return false }
                return armed.onDemand.requiresSSID
            }
            return MacAppComposition(
                persistence: persistence,
                secretStore: secretStore,
                daemon: daemon,
                shell: shell,
                repository: repository,
                onDemandRelay: relay,
            )
        }

        #if DEBUG || WGEX_LAB_BUILD
            internal static func preview(root: URL, serviceFactory: () -> FakeServiceController) -> MacAppComposition {
                let persistence = MacPersistence(container: root, simulated: true)
                let secretStore = makeSecretStore(simulated: true, root: root)
                let access = makeProfileAccess(permitted: true, daemon: { nil })
                let repository = makeRepository(root: root, persistence: persistence, secretStore: secretStore, access: access)
                let service = serviceFactory()
                let backend = FakeTunnelBackend()
                let dependencies = fakeDependencies(service: service, backend: backend, persistence: persistence, repository: repository)
                let shell = MacShellModel(dependencies: dependencies)
                configureProfileAccess(access, shell: shell)
                return MacAppComposition(
                    persistence: persistence, secretStore: secretStore, daemon: nil, shell: shell, repository: repository,
                    fakeService: service,
                )
            }
        #endif

        private static func makeRepository(
            root: URL, persistence: MacPersistence, secretStore: any SecretStore, access: MacProfileDaemonAccess,
        ) -> MacProfileRepository {
            MacProfileRepository(
                container: root, store: persistence.store, secrets: secretStore,
                installProfile: access.install, removeProfile: access.remove, checkDeletion: access.checkRemoval,
            )
        }

        private static func makeSecretStore(simulated: Bool, root: URL) -> any SecretStore {
            #if WGEX_LAB_BUILD
                simulated ? InMemorySecretStore() : LabFileSecretStore(directory: root.appendingPathComponent("lab-secrets"))
            #elseif DEBUG
                simulated ? InMemorySecretStore() : KeychainSecretStore()
            #else
                KeychainSecretStore()
            #endif
        }

        private static func configureProfileAccess(_ access: MacProfileDaemonAccess, shell: MacShellModel) {
            access.isReady = { [weak shell] in
                guard let shell, case .connected = shell.daemonConnection else { return false }
                return shell.daemonRunning && shell.secureInstall == .verified
            }
            access.reportError = { [weak shell] in shell?.reportError($0) }
            access.localStatus = { [weak shell] in shell?.status ?? .idle }
        }

        private static func makeProfileAccess(permitted: Bool, daemon: @escaping () -> MacDaemonComposition?) -> MacProfileDaemonAccess {
            MacProfileDaemonAccess(permitted: permitted, prepare: { profile in
                guard permitted else { throw ServiceError.hostGuard }
                try await daemon()?.registerSecretReferences(profile)
            }, install: { profile in
                guard permitted else { throw ServiceError.hostGuard }
                try await daemon()?.client.install(profile)
            }, remove: { id, purge in
                guard permitted else { throw ServiceError.hostGuard }
                if let daemon = daemon() {
                    guard case .ok = try await daemon.client.request(.removeProfile(id, purgeSecrets: purge)) else {
                        throw DaemonError.malformedMessage
                    }
                }
            }, status: {
                guard permitted else { throw ServiceError.hostGuard }
                guard let daemon = daemon() else { return nil }
                guard case let .status(status) = try await daemon.client.request(.status) else { throw DaemonError.malformedMessage }
                return status
            })
        }

        /// The relay's two daemon streams come from the actor-isolated client when it starts running.
        private static func makeOnDemandRelay(_ daemon: MacDaemonComposition) -> MacOnDemandRelay {
            MacOnDemandRelay(
                requests: { await daemon.client.wifiNetworkRequests() },
                subscriptions: {
                    let states = await daemon.client.connectionStates()
                    let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
                    let task = Task {
                        for await state in states {
                            if case .connected = state {
                                continuation.yield()
                            }
                        }
                        continuation.finish()
                    }
                    continuation.onTermination = { _ in task.cancel() }
                    return stream
                },
                location: MacLocationAuthorisation(), wifi: MacWiFiReader(),
                clock: { XPCClock.continuousSeconds },
                report: { observation in try await daemon.client.reportWiFiNetwork(observation) },
            )
        }

        private static func daemonOperations(
            _ daemon: MacDaemonComposition,
            persistence: MacPersistence,
            repository: MacProfileRepository,
            relay: MacOnDemandRelay,
            uninstall: MacUninstallSteps,
            reportError: @escaping (any Error) -> Void,
        ) -> MacShellOperations {
            let startup = MacStartupController(
                saveDaemon: { profile, option in try await daemon.saveStartup(profile, options: option.profileOptions) },
                setLoginItem: MacLoginItemController.setEnabled,
                saveDocument: { try await persistence.store.save($0) }, loadProfiles: { try await persistence.store.list() },
            )
            let settings = MacGlobalSettingsController(send: { settings, authorization in
                guard case .ok = try await daemon.client.request(.setGlobalSettings(settings), authorization: authorization) else {
                    throw DaemonError.malformedMessage
                }
            }, grant: { try await SystemSecureInstallAuthorisation.grant() })
            return MacShellOperations(
                setGlobalSettings: { try await settings.set($0) },
                deleteProfile: {
                    try await repository.delete($0)
                    do { try await startup.synchronizeLoginItem() }
                    catch { reportError(error) }
                },
                errorCopy: MacAppErrorCopy.resolve,
                savePreferences: { try await persistence.save($0) },
                saveStartup: { try await startup.save($0, option: $1) },
                openCaptiveWindow: { seconds in
                    try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await daemon.openCaptiveWindow(seconds: seconds) }
                },
                closeCaptiveWindow: {
                    try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await daemon.closeCaptiveWindow() }
                },
                secureInstall: { try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await daemon.secureInstall() } },
                refreshDaemon: {
                    try await MacDaemonBridge
                        .mapDaemonError(preservingCopy: true) { try await daemon.start(profiles: persistence.store.list()) }
                    return true
                },
                armOnDemand: { profile in
                    relay.profileWillBeSavedOrArmed(profile)
                    try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await daemon.client.armOnDemand(profile.id) }
                },
                disarmOnDemand: { id in
                    try await MacDaemonBridge.mapDaemonError(preservingCopy: true) { try await daemon.client.disarmOnDemand(id) }
                },
                readLog: { since in try await logLines(daemon.client.logs(since: since)) },
                exportDiagnostics: { includeLogs in
                    // Explicit ids: the daemon scopes the archive to the profiles named and owned by this caller.
                    let ids = try await persistence.store.list().map(\.id)
                    return try await MacDaemonBridge.mapDaemonError(preservingCopy: true) {
                        try await daemon.client.diagnostics(DiagnosticsRequest(includeLogs: includeLogs, since: nil, profileIDs: ids))
                            .archive
                    }
                },
                uninstall: uninstall,
            )
        }

        /// The daemon's redacted lines as the log view holds them; the view scrubs them again on entry. Read failures are
        /// not routed through the error copy: the view shows the log as unavailable and retries on its next read.
        private static func logLines(_ lines: [RedactedLogLine]) -> [MacLogLine] {
            lines.map { MacLogLine(date: $0.date, category: $0.category, message: $0.message) }
        }

        #if DEBUG || WGEX_LAB_BUILD
            private static func fakeDependencies(
                service: FakeServiceController?,
                backend: FakeTunnelBackend?,
                persistence: MacPersistence,
                repository: MacProfileRepository,
            ) -> MacShellDependencies {
                let service = service ?? FakeServiceController()
                let backend = backend ?? FakeTunnelBackend()
                return MacShellDependencies(backend: backend, service: service, simulated: true, operations: MacShellOperations(
                    setGlobalSettings: { $0 }, deleteProfile: { try await repository.delete($0) }, errorCopy: MacAppErrorCopy.resolve,
                    savePreferences: { try await persistence.save($0) },
                    saveStartup: { profile, option in
                        var updated = profile
                        updated.macOptions = option.profileOptions
                        try await persistence.store.save(updated)
                    },
                    openCaptiveWindow: { seconds in
                        let expires = Date().addingTimeInterval(Double(seconds))
                        var status = backend.currentStatus
                        status.phase = .captiveWindow(status.phase.generation ?? Generation(rawValue: 0), expires: expires)
                        status.protection = .captiveWindow(expires: expires)
                        backend.publish(status)
                    },
                    closeCaptiveWindow: {
                        var status = backend.currentStatus
                        status.phase = .reasserting(status.phase.generation ?? Generation(rawValue: 0), reason: .pathChanged)
                        status.protection = .blocked
                        backend.publish(status)
                    },
                    secureInstall: { .verified }, refreshDaemon: { true },
                    // Simulation: the fake service and the simulation container only; no daemon, keychain or defaults.
                    uninstall: MacUninstallSteps(
                        uninstallDaemon: { _ in }, unregisterDaemon: { try await service.unregister() }, unregisterLoginItem: {},
                        removeAppData: MacUninstallComposition.simulationRemoval(persistence, repository),
                        quit: { MacUninstallComposition.terminateAfterSheets() },
                    ),
                ))
            }
        #endif
    }
#endif
