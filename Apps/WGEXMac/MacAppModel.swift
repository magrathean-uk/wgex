// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if os(macOS)
    import AppKit
    import Foundation
    import Observation
    import os
    import UniformTypeIdentifiers
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXProfileStore
    #if DEBUG || WGEX_LAB_BUILD
        import WGEXTesting
    #endif
    import WGEXUI

    /// Application composition only. Testable presentation and actions live in WGEXUI.
    @MainActor @Observable
    public final class MacAppModel {
        public let shell: MacShellModel
        public let profileStore: ProfileStore
        public private(set) var windowEntryPoint: MacWindowEntryPoint?
        public var importing = false
        #if DEBUG
            public var showsDebug = false
        #endif
        public internal(set) var importErrorMessage: String?
        public internal(set) var importSaving = false
        public var importReviews: [ImportReviewModel] = []
        /// Create Empty Tunnel was chosen in the Add sheet; the editor opens once that sheet has gone.
        public internal(set) var pendingEmptyTunnel = false
        /// A setup step 3 action waiting for the setup sheet to go; the main window then runs it (never a sheet on a sheet).
        public internal(set) var pendingSetupAction: MacSetupAddAction?

        public internal(set) var editor: ProfileEditorModel?
        public internal(set) var exportModel: ExportModel?
        /// Asks for the all-tunnels key warning; the archive is only written after the user confirms it.
        public var exportAllConfirming = false
        public internal(set) var exportAllRunning = false
        /// Fixed copy for a failed all-tunnels export; never a payload or system description.
        public var exportAllMessage: String?
        @ObservationIgnored private let persistence: MacPersistence
        #if DEBUG || WGEX_LAB_BUILD
            @ObservationIgnored private let fakeService: FakeServiceController?
        #endif
        @ObservationIgnored private let daemon: MacDaemonComposition?
        /// Relays the Wi-Fi network name to the daemon for on-demand rules (ADR-030 section 3).
        @ObservationIgnored internal let onDemandRelay: MacOnDemandRelay?
        /// One store for the editor, import, export and the daemon composition: the Keychain with the
        /// real backend, memory with the fake one (lab run, 26 Oct 2026: a separate in-memory store left
        /// the daemon composition reading a Keychain that never held the imported keys).
        // swiftformat:disable:next redundantInternal
        @ObservationIgnored internal let secretStore: any SecretStore
        @ObservationIgnored private let preferencesLoader: () async throws -> MacPreferences
        @ObservationIgnored private let applyDockPolicy: (Bool) -> Void
        /// Ordered profile and secret transactions shared by import, editor and deletion.
        // swiftformat:disable:next redundantInternal
        @ObservationIgnored internal let repository: MacProfileRepository
        @ObservationIgnored private var loadTask: Task<Void, Never>?
        @ObservationIgnored private var observation: Task<Void, Never>?
        /// The launch read of the daemon's uninstall record; tests await it.
        @ObservationIgnored internal private(set) var uninstallCheck: Task<Void, Never>?
        /// Visibility-gated UI work; the backend protocol is unchanged.
        public private(set) var uiWork: MacUIWork?
        /// Login launches stay silent (menu bar only) until the user opens the window; the main scene reads this.
        public private(set) var launchPresentation = MacLaunchPresentation.unlaunched
        /// The launch was decided as a login launch (the login profile connects); kept after the window opens.
        public private(set) var launchedAtLogin = false
        /// The Hide Dock icon preference is known (loaded, or the load failed and defaults apply).
        @ObservationIgnored private var preferencesLoaded = false
        /// Explicit main-window opens waiting for a scene to perform them (the window scene never opens itself).
        public private(set) var pendingWindowOpens = 0
        /// The main window's open action, installed by a SwiftUI view that is live from launch (the app commands).
        /// Until it exists, opens stay queued in `pendingWindowOpens`.
        @ObservationIgnored private var windowOpener: (() -> Void)?
        /// Read once per composition, never from Settings.body.
        public let acknowledgements: String = {
            guard let url = Bundle.main.url(forResource: "THIRD_PARTY_NOTICES", withExtension: "md"),
                  let text = try? String(contentsOf: url, encoding: .utf8) else { return MacStrings.acknowledgementsUnavailable }
            return text
        }()

        /// Takes ownership of the platform adapters and the shared profile transaction store.
        internal init(
            composition: MacAppComposition,
            preferencesLoader: (() async throws -> MacPreferences)?,
            applyDockPolicy: @escaping (Bool) -> Void,
        ) {
            persistence = composition.persistence
            profileStore = composition.persistence.store
            secretStore = composition.secretStore
            repository = composition.repository
            daemon = composition.daemon
            onDemandRelay = composition.onDemandRelay
            shell = composition.shell
            // The Mac's store admits tunnels saved without an address or a server (DEC-088); the shell refuses to start them.
            shell.refusesIncompleteTunnels = true
            self.preferencesLoader = preferencesLoader ?? { try await composition.persistence.load() }
            self.applyDockPolicy = applyDockPolicy
            #if DEBUG || WGEX_LAB_BUILD
                fakeService = composition.fakeService
            #endif
            MacDaemonBridge.configure(daemon, shell: shell)
            uiWork = MacUIWork(shell: shell)
            // After an uninstall nothing may write preferences or profiles back on the way out.
            shell.uninstall.beforeQuit = { [weak self] in self?.stopObserving() }
        }

        /// Decides the launch kind from the launch Apple event at will-finish-launching, before any window is
        /// presented. A login launch drops the Dock icon; an ordinary launch requests the main window once; with no
        /// current event the launch stays silent until `didFinishLaunching(event:)`. Returns whether it is a login launch.
        @discardableResult
        public func willFinishLaunching(event: NSAppleEventDescriptor?) -> Bool {
            apply(.launch(MacLoginLaunch.signals(event)))
            return launchedAtLogin
        }

        /// Settles a launch still undecided at will-finish-launching from the event AppKit makes current at
        /// did-finish-launching; a decided launch is left alone. Returns whether it is a login launch.
        @discardableResult
        public func didFinishLaunching(event: NSAppleEventDescriptor?) -> Bool {
            if !launchPresentation.settled {
                apply(.launch(MacLoginLaunch.signals(event) ?? Self.noEventSignals))
            }
            return launchedAtLogin
        }

        /// No event even at did-finish-launching: nothing marks a login launch, so it is an ordinary one.
        private static let noEventSignals = MacLaunchSignals(isOpenApplication: false, loginItemFlag: false, sender: nil)

        /// Records how the app was launched. The main window scene is suppressed at launch, so an ordinary
        /// launch queues the one explicit open and a login launch queues none.
        public func beginLaunch(isLoginLaunch: Bool) {
            let signals = MacLaunchSignals(isOpenApplication: true, loginItemFlag: isLoginLaunch, sender: nil)
            launchPresentation = .unlaunched
            launchedAtLogin = false
            pendingWindowOpens = 0
            apply(.launch(signals))
        }

        /// A reopen (Dock click, Finder, Spotlight) is the user asking for the window: end the silent launch
        /// and, when no window is showing, queue an explicit open.
        public func reopenRequested(hasVisibleWindows: Bool) {
            shell.routeWindow(.reopen)
            apply(.reopen(hasVisibleWindows: hasVisibleWindows))
        }

        /// Runs the pure launch decision and carries out its Dock and window outcome. The Dock policy is applied
        /// only when the silent state changes; otherwise the preference load applies it. Before the preferences
        /// load, a decision that would show the Dock waits for the load, so a Hide Dock icon preference never flashes it.
        private func apply(_ request: MacLaunchRequest) {
            let wasSilent = launchPresentation.silent
            let decision = MacLaunchPresentation.decide(request, from: launchPresentation, hideDockIcon: shell.preferences.hideDockIcon)
            if case .launch = request, !launchPresentation.settled, decision.presentation.settled {
                launchedAtLogin = decision.presentation.silent
            }
            launchPresentation = decision.presentation
            if decision.opensWindow {
                pendingWindowOpens += 1
            }
            if wasSilent != launchPresentation.silent {
                applyLaunchDock(hidesDock: decision.hidesDock)
            }
        }

        /// Hiding the Dock applies at once; showing it waits until the Hide Dock icon preference is known.
        private func applyLaunchDock(hidesDock: Bool) {
            if hidesDock || preferencesLoaded {
                applyDockPolicy(hidesDock)
            }
        }

        /// Consumed by the scene that holds `openWindow`; true once per queued request.
        public func takePendingWindowOpen() -> Bool {
            guard pendingWindowOpens > 0 else { return false }
            pendingWindowOpens -= 1
            return true
        }

        /// Performs every queued open through the scene's open-window action; the one place the queue is consumed.
        public func dispatchPendingWindowOpens(_ open: () -> Void) {
            while takePendingWindowOpen() {
                open()
            }
        }

        /// The user asked for the window (menu Open, import, reopen): the Dock icon returns unless Hide Dock icon is on.
        public func windowRequested() {
            if launchPresentation.windowRequested() {
                applyLaunchDock(hidesDock: launchPresentation.hidesDock(hideDockIcon: shell.preferences.hideDockIcon))
            }
        }

        /// Applies the Dock policy from the launch presentation and the Hide Dock icon preference.
        public func applyDock() {
            applyDockPolicy(launchPresentation.hidesDock(hideDockIcon: shell.preferences.hideDockIcon))
        }

        /// Every scene joins the same load task before it can inspect preferences.
        public func start() async {
            if let loadTask {
                await loadTask.value
                guard !loadTask.isCancelled else { return }
                beginObserving()
                return
            }
            let task = Task { await self.loadPreferencesAndProfiles() }
            loadTask = task
            await task.value
            guard !task.isCancelled else { return }
            beginObserving()
        }

        private func loadPreferencesAndProfiles() async {
            do {
                let preferences = try await preferencesLoader()
                guard !Task.isCancelled else { return }
                shell.preferences = preferences
            } catch { shell.reportError(error) }
            guard !Task.isCancelled else { return }
            preferencesLoaded = true
            applyDock()
            do {
                let profiles = try await profileStore.list()
                guard !Task.isCancelled else { return }
                shell.profiles = profiles
                shell.applyInitialTunnel()
                if await !profileStore.takeQuarantinedProfiles().isEmpty {
                    shell.reportQuarantinedProfiles()
                }
            } catch { shell.reportError(error) }
            if shell.simulated, shell.profiles.isEmpty {
                await loadFixture(name: "Example · Mac")
            }
            guard !Task.isCancelled else { return }
            uninstallCheck = Task { await self.offerToFinishUninstall() }
        }

        /// An uninstall the daemon already holds (started from the CLI) is offered for finishing in the main window, which
        /// opens for it even after a login launch. Runs beside launch so a slow daemon never delays it.
        private func offerToFinishUninstall() async {
            await shell.uninstall.checkAtLaunch()
            guard shell.uninstall.finishOffered else { return }
            windowRequested()
            pendingWindowOpens += 1
        }

        private func beginObserving() {
            guard observation == nil else { return }
            if uiWork == nil {
                uiWork = MacUIWork(shell: shell)
            }
            uiWork?.observePreferences()
            observation = Task { [shell, daemon, onDemandRelay] in
                async let tunnel: Void = shell.observeTunnel()
                async let service: Void = shell.observeService()
                async let connection: Void = MacDaemonBridge.observeConnection(daemon?.client, shell: shell)
                async let relay: Void = onDemandRelay?.run() ?? ()
                _ = await (tunnel, service, connection, relay)
            }
        }

        /// The application delegate calls this on return from System Settings as well as activation.
        public func applicationActivated() async {
            await shell.applicationActivated()
            guard shell.serviceState == .enabled, !repository.isBusy else { return }
            do { try await repository.reconcile() }
            catch { shell.reportError(error) }
            do {
                let baseline = shell.profiles
                let loaded = try await profileStore.list()
                guard !repository.isBusy else { return }
                shell.profiles = Self.mergeProfiles(loaded: loaded, baseline: baseline, current: shell.profiles)
                shell.reselectAfterReload()
                if await !profileStore.takeQuarantinedProfiles().isEmpty {
                    shell.reportQuarantinedProfiles()
                }
            } catch { shell.reportError(error) }
        }

        public func stopObserving() {
            uiWork?.stop()
            uiWork = nil
            observation?.cancel()
            observation = nil
            loadTask?.cancel()
            loadTask = nil
        }

        public func simulateApproval() {
            #if DEBUG || WGEX_LAB_BUILD
                fakeService?.transition(to: .enabled)
            #endif
        }

        /// Fixed test material only; no arbitrary configuration String is accepted by the harness.
        public func loadFixture(name: String) async {
            #if DEBUG || WGEX_LAB_BUILD
                guard shell.simulated else { shell.reportError(ServiceError.unsupported); return }
                do {
                    guard let url = Bundle.main.url(forResource: "ipv6-dual-stack", withExtension: "conf") else {
                        throw MacWorkflowError.fixtureUnavailable
                    }
                    var bytes = try Array(Data(contentsOf: url))
                    let parsed = try parseWgQuick(&bytes, name: name.isEmpty ? "Example · Mac" : name)
                    guard !parsed.diagnostics.contains(where: { $0.severity == .error }) else { throw ServiceError.unsupported }
                    let profile = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
                    shell.profiles.append(profile)
                    if shell.canSelectProfile {
                        shell.selectByAction(profile.id)
                    }
                } catch { shell.reportError(error) }
            #endif
        }
    }

    /// Main-window routing: every entry point lands in the one window through an open action from a live view.
    public extension MacAppModel {
        /// Whether a live view has installed the main window's open action.
        var canOpenWindow: Bool {
            windowOpener != nil
        }

        /// Installs the open action from a live view and, after the current view update, performs any opens
        /// queued before it existed (the launch window, an uninstall offer, a menu click during launch).
        func installWindowOpener(_ open: @escaping () -> Void) {
            let first = windowOpener == nil
            windowOpener = open
            if first, pendingWindowOpens > 0 {
                Task { @MainActor [weak self] in self?.dispatchPendingWindowOpens() }
            }
        }

        /// Performs queued opens through the installed action; without one the queue is left untouched.
        func dispatchPendingWindowOpens() {
            guard let windowOpener else { return }
            dispatchPendingWindowOpens(windowOpener)
        }

        /// All user entry points use the sole main scene's open action.
        func requestWindow(_ entry: MacWindowEntryPoint, open: () -> Void) {
            routeWindow(entry)
            open()
        }

        /// Entry points outside SwiftUI (the status item menu) open through the installed action, or queue the open
        /// until a live view installs it.
        func requestWindow(_ entry: MacWindowEntryPoint) {
            routeWindow(entry)
            if let windowOpener {
                windowOpener()
            } else {
                pendingWindowOpens += 1
            }
        }

        /// An entry received by the existing window also suppresses automatic setup for that explicit action.
        func routeWindow(_ entry: MacWindowEntryPoint) {
            windowEntryPoint = entry
            shell.routeWindow(entry)
            windowRequested()
        }

        /// First-run setup stays inside the main window and never overrides an explicit destination.
        func presentInitialOnboarding() {
            guard windowEntryPoint == nil, !launchPresentation.silent, !shell.preferences.onboardingComplete else { return }
            shell.showsOnboarding = true
        }
    }

#endif
