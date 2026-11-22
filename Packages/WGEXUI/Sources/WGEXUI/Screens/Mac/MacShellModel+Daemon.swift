// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    /// App-supplied daemon operations kept separate from install repair and local status replay.
    @MainActor
    public struct MacDaemonHooks {
        /// Explicit update authorisation and registration; never called on reconnect.
        public var finishUpdate: (() async throws -> Void)?
        /// Shared kernel clock supplied by the daemon adapter; previews use process uptime.
        public var continuousNow: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
        /// Requests measured status from the service, reconnecting if necessary.
        public var refreshStatus: (() async throws -> Void)?
        /// Stops the service's current intent, even while a start is pending.
        public var stopCurrent: (() async throws -> Void)?
        /// Read-only secure-install measurement; never prompts for authorisation.
        public var secureInstallStatus: (() async throws -> SecureInstallState)?
        /// Refreshes service approval on application activation.
        public var refreshServiceApproval: (() -> Void)?
        /// Propagates the existing surface visibility signal to automatic reconnection.
        public var visibility: ((Bool) -> Void)?

        /// An empty set supports previews without constructing system services.
        public init() {}
    }

    /// Update copy is independent of protection evidence.
    public enum MacUpdateHandoffState: Sendable, Equatable {
        /// No registration replacement is pending.
        case idle
        /// The service is replacing an older build.
        case finishing
        /// The replacement needs approval through the existing System Settings deep link.
        case needsApproval
    }

    public extension MacShellModel {
        /// Announces availability without starting an update or displaying an admin prompt.
        func offerUpdate(_ available: Bool) {
            updateAvailable = available
        }

        /// Only the service-card/onboarding button invokes this administrative action.
        func finishUpdate() async {
            guard !hostGuarded, !busy, let finish = daemonHooks.finishUpdate else { return }
            await perform {
                do {
                    try await finish()
                    self.updateAvailable = false
                    self.receiveUpdateHandoff(.idle)
                } catch {
                    self.receiveUpdateHandoff(.idle)
                    throw error
                }
            }
        }

        /// Shows registration progress without making a new protection claim.
        func receiveUpdateHandoff(_ state: MacUpdateHandoffState) {
            updateHandoff = state
            switch state {
            case .idle: operationMessage = nil
            case .finishing: operationMessage = MacStrings.finishingUpdate
            case .needsApproval:
                operationMessage = MacStrings.needsApprovalAgain
                receiveService(.requiresApproval)
            }
        }

        /// Reads install evidence without taking the mutation/busy slot.
        func refreshSecureInstall() async {
            guard let read = daemonHooks.secureInstallStatus, daemonRunning, !hostGuarded else { return }
            let revision = connectionRevision
            do {
                let measured = try await read()
                guard revision == connectionRevision, !Task.isCancelled else { return }
                secureInstall = measured
            } catch {
                guard revision == connectionRevision, !Task.isCancelled else { return }
                secureInstall = .notReporting
            }
        }
    }
#endif
