// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// Connection metadata supplied by the app, independent of the backend package.
    public enum MacDaemonConnectionState: Sendable, Equatable {
        case disconnected(lastError: String?)
        case connecting
        case connected(daemonBuild: Int)
    }

    /// Successful returns mean acknowledged state.
    @MainActor
    public struct MacShellOperations {
        /// Daemon-acknowledged global settings; the returned value replaces the local cache.
        public var setGlobalSettings: (MacGlobalSettings) async throws -> MacGlobalSettings
        /// Ordered daemon, secret and document deletion supplied by the app repository.
        public var deleteProfile: (TunnelProfile) async throws -> Void
        /// App-specific typed error adapter.
        public var errorCopy: (any Error) -> MacErrorCopy
        public var savePreferences: (MacPreferences) async throws -> Void
        public var saveStartup: (TunnelProfile, MacStartupOption) async throws -> Void
        public var openCaptiveWindow: (Int) async throws -> Void
        public var closeCaptiveWindow: () async throws -> Void
        public var secureInstall: () async throws -> SecureInstallState
        public var refreshDaemon: () async throws -> Bool
        /// Arms the profile on the daemon (ADR-030 `armOnDemand`); success means acknowledged. The app also asks for Location here
        /// when the profile's rule lists networks.
        public var armOnDemand: (TunnelProfile) async throws -> Void
        /// Disarms on the daemon, stopping the tunnel if it is intended (`disarmOnDemand`).
        public var disarmOnDemand: (UUID) async throws -> Void
        /// Reads the daemon's redacted tunnel and daemon log at or after a date (the read-only `logs` request); a backend
        /// without a log throws.
        public var readLog: (Date?) async throws -> [MacLogLine]
        /// The daemon's redacted diagnostics archive, with or without logs (`Request.diagnostics`), bytes unchanged.
        public var exportDiagnostics: (Bool) async throws -> Data
        /// The uninstall's daemon, service and app-data steps (M05-T10).
        public var uninstall: MacUninstallSteps

        public init(
            setGlobalSettings: @escaping (MacGlobalSettings) async throws -> MacGlobalSettings = { _ in throw ServiceError.unsupported },
            deleteProfile: @escaping (TunnelProfile) async throws -> Void = { _ in throw ServiceError.unsupported },
            errorCopy: @escaping (any Error) -> MacErrorCopy = { MacErrorCopy(error: $0) },
            savePreferences: @escaping (MacPreferences) async throws -> Void = { _ in },
            saveStartup: @escaping (TunnelProfile, MacStartupOption) async throws -> Void = { _, _ in throw ServiceError.unsupported },
            openCaptiveWindow: @escaping (Int) async throws -> Void = { _ in throw ServiceError.unsupported },
            closeCaptiveWindow: @escaping () async throws -> Void = { throw ServiceError.unsupported },
            secureInstall: @escaping () async throws -> SecureInstallState = { throw ServiceError.unsupported },
            refreshDaemon: @escaping () async throws -> Bool = { false },
            armOnDemand: @escaping (TunnelProfile) async throws -> Void = { _ in throw ServiceError.unsupported },
            disarmOnDemand: @escaping (UUID) async throws -> Void = { _ in throw ServiceError.unsupported },
            readLog: @escaping (Date?) async throws -> [MacLogLine] = { _ in throw ServiceError.unsupported },
            exportDiagnostics: @escaping (Bool) async throws -> Data = { _ in throw ServiceError.unsupported },
            uninstall: MacUninstallSteps = MacUninstallSteps(),
        ) {
            self.setGlobalSettings = setGlobalSettings
            self.deleteProfile = deleteProfile
            self.errorCopy = errorCopy
            self.savePreferences = savePreferences
            self.saveStartup = saveStartup
            self.openCaptiveWindow = openCaptiveWindow
            self.closeCaptiveWindow = closeCaptiveWindow
            self.secureInstall = secureInstall
            self.refreshDaemon = refreshDaemon
            self.armOnDemand = armOnDemand
            self.disarmOnDemand = disarmOnDemand
            self.readLog = readLog
            self.exportDiagnostics = exportDiagnostics
            self.uninstall = uninstall
        }
    }

    @MainActor
    public struct MacShellDependencies {
        public let backend: any TunnelBackend
        public let service: any ServiceControlling
        public let simulated: Bool
        public let hostGuarded: Bool
        public let operations: MacShellOperations

        public init(
            backend: any TunnelBackend,
            service: any ServiceControlling,
            simulated: Bool,
            hostGuarded: Bool = false,
            operations: MacShellOperations = MacShellOperations(),
        ) {
            self.backend = backend
            self.service = service
            self.simulated = simulated
            self.hostGuarded = hostGuarded
            self.operations = operations
        }

        #if DEBUG || WGEX_LAB_BUILD
            /// Debug/Lab factories are lazy: fake selection never constructs a real service controller.
            public static func select(arguments: [String], fake: () -> Self, real: () -> Self) -> Self {
                arguments.contains("-WGEXFakeBackend") ? fake() : real()
            }
        #endif
    }
#endif
