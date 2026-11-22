// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Observation
    import WGEXCore

    /// What the daemon reports about an uninstall it holds, read at launch (M05-T07 `UninstallProgress`).
    public nonisolated struct MacPendingUninstall: Sendable, Equatable {
        /// Every daemon step is done; only the background service and login item remain.
        public var completed: Bool
        /// The uninstall was asked to purge the daemon's state.
        public var purgeState: Bool

        public init(completed: Bool, purgeState: Bool) {
            self.completed = completed
            self.purgeState = purgeState
        }
    }

    /// The uninstall's platform steps, supplied by the app composition (DEC-037). None of them registers anything.
    @MainActor
    public struct MacUninstallSteps {
        /// Asks for administrator approval and runs the daemon's `uninstall(purgeState:)`; returns when every daemon step is done.
        public var uninstallDaemon: (Bool) async throws -> Void
        /// Unregisters the background service through `ServiceController`.
        public var unregisterDaemon: () async throws -> Void
        /// Unregisters the login item through `ServiceController`.
        public var unregisterLoginItem: () async throws -> Void
        /// Deletes the app's profiles, keychain items and preferences.
        public var removeAppData: () async throws -> Void
        /// The uninstall the daemon holds, or nil when it holds none or cannot be reached.
        public var pending: () async -> MacPendingUninstall?
        /// Ends the app once the final screen is acknowledged.
        public var quit: () -> Void

        public init(
            uninstallDaemon: @escaping (Bool) async throws -> Void = { _ in throw ServiceError.unsupported },
            unregisterDaemon: @escaping () async throws -> Void = { throw ServiceError.unsupported },
            unregisterLoginItem: @escaping () async throws -> Void = { throw ServiceError.unsupported },
            removeAppData: @escaping () async throws -> Void = { throw ServiceError.unsupported },
            pending: @escaping () async -> MacPendingUninstall? = { nil },
            quit: @escaping () -> Void = {},
        ) {
            self.uninstallDaemon = uninstallDaemon
            self.unregisterDaemon = unregisterDaemon
            self.unregisterLoginItem = unregisterLoginItem
            self.removeAppData = removeAppData
            self.pending = pending
            self.quit = quit
        }
    }

    /// The uninstall sequence: the daemon's uninstall, then the background service and the login item, then (only when the
    /// box is ticked) the app's own profiles, keys and preferences. Each stage runs once: a failure keeps its place, and a
    /// retry resumes there, so a daemon failure unregisters nothing and an unregister failure never repeats the daemon step.
    @MainActor @Observable
    public final class MacUninstall {
        public enum Stage: Int, Comparable, Sendable {
            case daemon, daemonService, loginItem, appData, finished

            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.rawValue < rhs.rawValue
            }
        }

        public enum Phase: Equatable {
            /// Waiting for the user to confirm.
            case idle
            case working
            /// The stage that failed is retried by `run()`.
            case failed(String)
            /// The final screen: WGEX can be moved to the Bin.
            case finished
        }

        /// "Also remove tunnels and settings", off by default. Fixed once the daemon step has succeeded.
        public var removeProfilesAndSettings = false
        public private(set) var phase = Phase.idle
        public private(set) var stage = Stage.daemon
        /// The daemon holds an uninstall started elsewhere (the CLI); the main window offers to finish it. It stays set
        /// through the final screen, which only Quit ends.
        public var finishOffered = false
        /// True when this run finishes an uninstall the daemon already holds.
        public private(set) var finishing = false
        /// Runs before `quit`, so the app stops writing preferences or profiles back after the removal.
        @ObservationIgnored public var beforeQuit: () -> Void = {}
        /// The daemon's own purge choice when finishing one it holds; the app's box stays off.
        @ObservationIgnored private var pendingPurge = false
        @ObservationIgnored private let steps: MacUninstallSteps
        @ObservationIgnored private let copy: (any Error) -> String

        public init(steps: MacUninstallSteps, errorCopy: @escaping (any Error) -> String = { MacErrorCopy(error: $0).message }) {
            self.steps = steps
            copy = errorCopy
        }

        /// The production wiring: the shell's uninstall steps and its error copy.
        public convenience init(operations: MacShellOperations) {
            let errorCopy = operations.errorCopy
            self.init(steps: operations.uninstall, errorCopy: { errorCopy($0).message })
        }

        public var isWorking: Bool {
            phase == .working
        }

        /// The box can change only before the daemon step has succeeded, and never while finishing.
        public var canChoosePurge: Bool {
            stage == .daemon && !finishing && !isWorking
        }

        /// The daemon step asks for administrator approval only when it still has to run.
        public var needsAdministrator: Bool {
            stage == .daemon
        }

        /// Confirm and Retry both call this. A second call while one runs, or after the end, is ignored.
        public func run() async {
            guard phase != .working, phase != .finished else { return }
            phase = .working
            while stage != .finished {
                let (step, failure) = action(for: stage)
                do { try await step() } catch {
                    phase = .failed("\(failure) \(copy(error))")
                    return
                }
                stage = Stage(rawValue: stage.rawValue + 1) ?? .finished
            }
            // A finish offer stays presented: its sheet now shows the final screen and its Quit action.
            phase = .finished
        }

        /// One stage's step and the copy shown when it fails. App data goes only when ticked, and never on a finish.
        private func action(for stage: Stage) -> (() async throws -> Void, String) {
            switch stage {
            case .daemon:
                let purge = finishing ? pendingPurge : removeProfilesAndSettings
                return ({ try await self.steps.uninstallDaemon(purge) }, MacStrings.uninstallDaemonFailed)
            case .daemonService: return (steps.unregisterDaemon, MacStrings.uninstallServiceFailed)
            case .loginItem: return (steps.unregisterLoginItem, MacStrings.uninstallServiceFailed)
            case .appData:
                let remove = removeProfilesAndSettings && !finishing
                return (remove ? steps.removeAppData : {}, MacStrings.uninstallAppDataFailed)
            case .finished: return ({}, "")
            }
        }

        /// Reads the daemon once at launch. A completed uninstall (the CLI's) is finished without a second administrator
        /// prompt: only the two services remain. One still in progress resumes at the daemon step with its own purge choice.
        /// The app's profiles and keys are never removed by a finish.
        public func checkAtLaunch() async {
            // The state is checked again after the read: the user may have started an uninstall meanwhile.
            guard phase == .idle, stage == .daemon, !finishing, let pending = await steps.pending(),
                  phase == .idle, stage == .daemon else { return }
            finishing = true
            removeProfilesAndSettings = false
            stage = pending.completed ? .daemonService : .daemon
            pendingPurge = pending.purgeState
            finishOffered = true
        }

        /// The final screen's only action. The sheet is dismissed first (the offer's flag cleared, and `dismissSheet` for the
        /// host that presents it by its own state), then `steps.quit` runs: a sheet still attached blocks termination.
        public func quit(dismissSheet: () -> Void = {}) {
            guard phase == .finished else { return }
            beforeQuit()
            finishOffered = false
            dismissSheet()
            steps.quit()
        }

        /// Cancel or "Not Now": a later open shows the same place, failure included.
        public func dismissOffer() {
            finishOffered = false
        }
    }
#endif
