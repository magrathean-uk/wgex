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

    /// The uninstall's production steps (M05-T10, DEC-037). `MacAppComposition.real` calls this with the XPC client, the admin
    /// grant and the two `ServiceController`s; tests call it with a stub transport, recording service operations and stores.
    /// Nothing here registers a service: both service steps only unregister, behind the controller's host guard.
    @MainActor
    internal enum MacUninstallComposition {
        internal static func steps(
            client: DaemonClient,
            permitted: Bool,
            authorize: @escaping @Sendable () async throws -> any SecureInstallGrant,
            daemonService: ServiceController,
            loginItem: ServiceController,
            repository: MacProfileRepository,
            persistence: MacPersistence,
            removeKeychainItems: @escaping () async throws -> Void,
            removePreferences: @escaping () -> Void,
            quit: @escaping () -> Void,
        ) -> MacUninstallSteps {
            MacUninstallSteps(
                uninstallDaemon: { purge in
                    guard permitted else { throw ServiceError.hostGuard }
                    // The grant stays alive until the daemon has verified the external form and replied.
                    let grant = try await authorize()
                    try await MacDaemonBridge.mapDaemonError(preservingCopy: true) {
                        try await client.uninstall(purgeState: purge, authorization: grant.externalForm)
                    }
                    withExtendedLifetime(grant) {}
                },
                unregisterDaemon: { try await daemonService.unregisterIfRegistered() },
                unregisterLoginItem: { try await loginItem.unregisterIfRegistered() },
                removeAppData: {
                    // No preference write may land after the container is gone: refuse new ones, wait out the active one.
                    await persistence.suspendWrites()
                    try await repository.removeAll()
                    try await removeKeychainItems()
                    removePreferences()
                },
                pending: {
                    guard permitted, let progress = try? await client.statusTelemetry().uninstall else { return nil }
                    return MacPendingUninstall(completed: progress.completed, purgeState: progress.purgeState)
                },
                quit: quit,
            )
        }

        /// Quits once every sheet is gone: AppKit refuses to terminate while a window has a sheet attached, and the final
        /// screen's own sheet is still closing when Quit runs. A sheet that outlasts the wait is ended before terminating.
        /// Terminate itself is requested from the main run loop, never inline in this Task: `applicationShouldTerminate`
        /// answers `.terminateLater` and the flush replies from main-actor jobs, which cannot run while the job that called
        /// `terminate` is still on the main queue (M05-T17).
        @discardableResult
        internal static func terminateAfterSheets(
            sheetsOpen: @escaping @MainActor () -> Bool = { NSApplication.shared.windows.contains { $0.attachedSheet != nil } },
            endSheets: @escaping @MainActor () -> Void = {
                for window in NSApplication.shared.windows {
                    if let sheet = window.attachedSheet {
                        window.endSheet(sheet)
                    }
                }
            },
            schedule: @escaping @MainActor (@escaping @MainActor () -> Void) -> Void = onMainRunLoop,
            terminate: @escaping @MainActor () -> Void = { NSApplication.shared.terminate(nil) },
        ) -> Task<Void, Never> {
            Task { @MainActor in
                await quitAfterSheets(sheetsOpen: sheetsOpen, endSheets: endSheets, terminate: { schedule(terminate) })
            }
        }

        /// The run-loop entry point: `body` runs from a main run-loop callout in the common modes, outside any Swift
        /// concurrency job, so a nested run loop it starts can still drain the main queue.
        internal static func onMainRunLoop(_ body: @escaping @MainActor () -> Void) {
            RunLoop.main.perform(inModes: [.common]) {
                MainActor.assumeIsolated { body() }
            }
        }

        /// Waits up to `attempts` turns of `interval` for the sheets to close, ends any that remain, then terminates.
        internal static func quitAfterSheets(
            sheetsOpen: () -> Bool, endSheets: () -> Void, terminate: () -> Void,
            attempts: Int = 40, interval: Duration = .milliseconds(50),
        ) async {
            var left = attempts
            while sheetsOpen(), left > 0 {
                left -= 1
                try? await Task.sleep(for: interval)
            }
            if sheetsOpen() {
                endSheets()
            }
            terminate()
        }

        /// The simulation's app data: its container only, with preference writes stopped first as in `steps`.
        internal static func simulationRemoval(
            _ persistence: MacPersistence, _ repository: MacProfileRepository,
        ) -> () async throws -> Void {
            {
                await persistence.suspendWrites()
                try await repository.removeAll()
            }
        }

        /// The keychain composition removes every item of this build, orphans included; the file and memory stores live
        /// under the container or in memory and need nothing more.
        internal static func keychainRemoval(_ store: any SecretStore) -> () async throws -> Void {
            guard let keychain = store as? KeychainSecretStore else { return {} }
            return { try await keychain.deleteAll() }
        }

        /// The app's own defaults domain (window and scene state); its preferences file lives in the container.
        internal static func removeDefaults() {
            guard let domain = Bundle.main.bundleIdentifier else { return }
            UserDefaults.standard.removePersistentDomain(forName: domain)
        }
    }
#endif
