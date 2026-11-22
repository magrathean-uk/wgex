// SPDX-License-Identifier: MIT
#if os(macOS)
    import os
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXUI

    /// Keeps safe display copy from the original wire error alongside its flattened machine category.
    public struct MacDaemonOperationFailure: Error {
        public let original: DaemonError
        public let copy: MacErrorCopy
        public let mapped: TunnelError

        public init(original: DaemonError) {
            self.original = original
            copy = MacAppErrorCopy.resolve(original)
            mapped = original.tunnelError
        }
    }

    /// Feeds the daemon client's connection states into the Mac shell.
    public enum MacDaemonBridge {
        /// Maps machine-facing categories, optionally retaining the original daemon category's safe copy.
        public static func mapDaemonError<Value>(
            preservingCopy: Bool = false, _ action: () async throws -> Value,
        ) async throws -> Value {
            do { return try await action() }
            catch {
                #if WGEX_LAB_BUILD
                    // The copy adapter selects fixed catalogue text; no reflected type or payload reaches logs.
                    let label = MacAppErrorCopy.resolve(error).title
                    Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "app")
                        .log(
                            "Daemon call failed: \(label, privacy: .public)",
                        )
                #endif
                if preservingCopy, let daemon = error as? DaemonError {
                    throw MacDaemonOperationFailure(original: daemon)
                }
                throw (error as? DaemonError)?.tunnelError ?? error
            }
        }

        /// Installs read-only measurement and cancellation paths without opening XPC.
        @MainActor public static func configure(_ daemon: MacDaemonComposition?, shell: MacShellModel) {
            guard let daemon, !shell.hostGuarded else { return }
            if let service = shell.service as? ServiceController {
                shell.daemonHooks.refreshServiceApproval = { service.refresh() }
            }
            shell.daemonHooks.finishUpdate = { [weak shell] in
                guard let shell else { return }
                do {
                    try await daemon.finishUpdate(service: shell.service) { state in
                        await shell.receiveConnection(.connecting)
                        await shell.receiveUpdateHandoff(state == .needsApproval ? .needsApproval : .finishing)
                    }
                } catch {
                    shell.receiveUpdateHandoff(.idle)
                    await daemon.client.republishConnectionState()
                    await apply(daemon.client.currentConnectionState(), shell: shell)
                    throw error
                }
            }
            shell.daemonHooks.continuousNow = { XPCClock.continuousSeconds }
            shell.daemonHooks.refreshStatus = { try await daemon.client.refreshStatus() }
            shell.daemonHooks.stopCurrent = { try await daemon.client.stopCurrent() }
            shell.daemonHooks.secureInstallStatus = { try await daemon.secureInstallStatus() }
            shell.daemonHooks.visibility = { visible in Task { await daemon.client.setSurfaceVisible(visible) } }
        }

        @MainActor private static func apply(_ state: DaemonConnectionState, shell: MacShellModel) {
            switch state {
            case let .connected(build): shell.receiveConnection(.connected(daemonBuild: build))
            case let .secureInstallRequired(build):
                shell.receiveConnection(.connected(daemonBuild: build))
                shell.reportSecureInstallRequired()
            case .connecting: shell.receiveConnection(.connecting)
            case let .disconnected(error): shell.receiveConnection(.disconnected(lastError: error?.rawValue))
            }
        }

        /// Observes until cancelled; does nothing without a client or while the host guard refuses.
        public static func observeConnection(_ client: DaemonClient?, shell: MacShellModel) async {
            guard let client, !shell.hostGuarded else { return }
            for await state in await client.connectionStates() {
                guard !Task.isCancelled else { return }
                switch state {
                case let .connected(build):
                    shell.receiveConnection(.connected(daemonBuild: build))
                    await shell.offerUpdate(build < client.clientBuild)
                case let .secureInstallRequired(build):
                    shell.receiveConnection(.connected(daemonBuild: build))
                    shell.reportSecureInstallRequired()
                case .connecting: shell.receiveConnection(.connecting)
                case let .disconnected(error): shell.receiveConnection(.disconnected(lastError: error?.rawValue))
                }
            }
        }
    }
#endif
