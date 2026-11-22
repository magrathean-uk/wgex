// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    /// First-run setup in three sheets (SPEC 7, M07-T06).
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacSetupTests {
        private func shell(
            service: FakeServiceController = FakeServiceController(),
            guarded: Bool = false,
        ) -> MacShellModel {
            MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(), service: service, simulated: false, hostGuarded: guarded,
                operations: MacShellOperations(refreshDaemon: { true }),
            ))
        }

        @Test func `three ordered steps carry the SPEC titles and texts`() {
            #expect(MacOnboardingStep.ordered == [.welcome, .backgroundService, .addTunnel])
            #expect(MacOnboardingStep.ordered.map(\.title) == ["Welcome to WGEX", "Allow WGEX in the Background", "Add a Tunnel"])
            #expect(MacOnboardingStep.welcome.message
                == "WGEX connects this Mac to your own WireGuard server. There are no accounts, no provided servers and no analytics.")
            #expect(MacOnboardingStep.backgroundService.message
                == "WGEX keeps your tunnel running after you close this window. macOS asks you to allow that once.")
            #expect(MacOnboardingStep.addTunnel.message
                == "Use a WireGuard configuration made for this Mac. You can also drop a file anywhere on this window.")
            #expect(MacOnboardingStep.ordered.map(\.progressLabel) == ["Step 1 of 3", "Step 2 of 3", "Step 3 of 3"])
            #expect(MacStrings.backgroundService == "Background service")
            #expect(MacStrings.openSystemSettingsEllipsis == "Open System Settings…")
            #expect(MacStrings.continueLabel == "Continue")
            #expect(MacStrings.notNow == "Not Now")
        }

        @Test(arguments: ServiceState.allCases, [false, true])
        func `step 2 Continue waits until macOS reports the service running`(state: ServiceState, running: Bool) {
            let model = shell()
            model.revisit(.backgroundService)
            model.receiveService(state)
            if running {
                model.receiveConnection(.connected(daemonBuild: 1))
            }
            #expect(model.canAdvance == (state == .enabled && running))
        }

        @Test func `the Background service row says its state in words`() {
            #expect(MacOnboardingStep.serviceWord(state: .notRegistered, running: false) == "Needs approval")
            #expect(MacOnboardingStep.serviceWord(state: .requiresApproval, running: false) == "Needs approval")
            #expect(MacOnboardingStep.serviceWord(state: .enabled, running: false) == "Starting…")
            #expect(MacOnboardingStep.serviceWord(state: .enabled, running: true) == "Running")
            #expect(MacOnboardingStep.serviceWord(state: .notFound, running: false) == "Unavailable")
        }

        @Test func `entering step 2 registers once and Continue then completes setup without secure install`() async {
            let service = FakeServiceController()
            let model = shell(service: service)
            await model.advanceOnboarding()
            #expect(model.onboardingStep == .backgroundService)
            #expect(service.calls == [.register])
            #expect(model.serviceState == .requiresApproval)
            #expect(model.setupServiceProblem == nil)
            #expect(!model.setupOffersRegisterAgain)
            // Continue stays off and a refused press registers nothing more.
            await model.advanceOnboarding(); await model.advanceOnboarding()
            #expect(service.calls == [.register])
            service.transition(to: .enabled)
            await model.applicationActivated()
            #expect(model.canAdvance)
            #expect(service.calls == [.register])
            await model.advanceOnboarding()
            #expect(model.onboardingStep == .addTunnel)
            #expect(model.preferences.onboardingComplete)
            #expect(model.secureInstall != .verified)
        }

        @Test func `step 2 with the service already running offers Continue at once and registers nothing`() async {
            let service = FakeServiceController(initial: .enabled)
            let model = shell(service: service)
            await model.advanceOnboarding()
            #expect(model.onboardingStep == .backgroundService)
            #expect(model.canAdvance)
            #expect(service.calls.isEmpty)
            #expect(MacOnboardingStep.serviceWord(state: model.serviceState, running: model.daemonRunning) == "Running")
        }

        @Test func `the host guard never registers and says why`() async {
            let service = FakeServiceController()
            let model = shell(service: service, guarded: true)
            await model.advanceOnboarding()
            #expect(model.onboardingStep == .backgroundService)
            #expect(service.calls.isEmpty)
            #expect(!model.canAdvance)
            #expect(model.setupServiceProblem == MacShellCopy.hostGuard)
            #expect(!model.setupOffersRegisterAgain)
        }

        @Test func `a refused registration shows one line and Register Again, which retries`() async {
            let service = FakeServiceController()
            service.faults.arm("register", error: ServiceError.system(code: 42))
            let model = shell(service: service)
            await model.advanceOnboarding()
            #expect(service.calls == [.register])
            #expect(model.serviceState == .notRegistered)
            #expect(model.setupRegistrationFailed)
            #expect(model.setupServiceProblem == MacStrings.backgroundServiceNotRegistered)
            #expect(model.setupOffersRegisterAgain)
            await model.registerFromSetup()
            #expect(service.calls == [.register, .register])
            #expect(model.serviceState == .requiresApproval)
            #expect(model.setupServiceProblem == nil)
            #expect(!model.setupOffersRegisterAgain)
        }

        @Test func `a service macOS cannot find is not registered on entry and offers Register Again`() async {
            let service = FakeServiceController(initial: .notFound)
            let model = shell(service: service)
            await model.advanceOnboarding()
            #expect(service.calls.isEmpty)
            #expect(model.setupServiceProblem == MacStrings.backgroundServiceNotFound)
            #expect(model.setupOffersRegisterAgain)
            #expect(!model.canAdvance)
        }

        @Test func `Not Now closes setup on the empty page, or on the SPEC 5_1 tunnel when tunnels exist`() {
            let empty = shell()
            empty.routeWindow(.setup)
            empty.revisit(.addTunnel)
            empty.routeWindow(.manageTunnels)
            #expect(!empty.showsOnboarding)
            #expect(!empty.showsSettings)
            #expect(empty.selectedProfileID == nil)
            let home = TunnelProfile(name: "Home")
            var office = TunnelProfile(name: "Office")
            office.macOptions.autoConnectAtLogin = true
            let model = shell()
            // Loaded as the app loads them: the SPEC 5.1 rule, not the first tunnel, picks the destination.
            model.profiles = [home, office]
            model.selectedProfileID = nil
            model.windowSelection = .settings(.general)
            model.routeWindow(.setup)
            #expect(model.showsOnboarding)
            #expect(model.onboardingStep == .welcome)
            model.revisit(.addTunnel)
            model.routeWindow(.manageTunnels)
            #expect(!model.showsOnboarding)
            #expect(!model.showsSettings)
            #expect(model.selectedProfileID == office.id)
        }

        @Test func `step 3 actions wait for the setup sheet to go and then run in the window`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = MacAppModel(arguments: ["-WGEXFakeBackend"], container: root, applyDockPolicy: { _ in })
            app.requestWindow(.setup) {}
            app.shell.revisit(.addTunnel)
            app.leaveSetup(then: .createEmpty)
            #expect(!app.shell.showsOnboarding)
            #expect(app.editor == nil)
            app.setupSheetDismissed()
            #expect(app.editor != nil)
            #expect(app.pendingSetupAction == nil)
            app.closeEditor()
            let file = EditorFixtures.root.appendingPathComponent("conf/ipv6-dual-stack.conf")
            app.requestWindow(.setup) {}
            app.leaveSetup(then: .drop([file]))
            #expect(!app.importing)
            app.setupSheetDismissed()
            #expect(app.importing)
            #expect(app.importReviews.count == 1)
            // Not Now leaves nothing pending: the dismissal opens nothing.
            app.cancelImport()
            app.requestWindow(.setup) {}
            app.shell.routeWindow(.manageTunnels)
            app.setupSheetDismissed()
            #expect(!app.importing && app.editor == nil)
        }

        @Test func `setup source has no QR, Back, Lockdown, start-up, secure install, icons or fixed colours`() throws {
            let view = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacOnboardingView.swift")
            for marker in [
                "qr", "QR", "Lockdown", "lockdown", "startup", "Startup", "secureInstall", "SecureInstall",
                "Image(systemName", "Color.", "revisit",
            ] {
                #expect(!view.contains(marker), "\(marker) in MacOnboardingView.swift")
            }
            #expect(!view.contains(/MacStrings\.back\b/), "MacStrings.back in MacOnboardingView.swift")
            #expect(view.contains("MacAddTunnelView("))
            #expect(view.contains("dismissTitle: MacStrings.notNow, dismiss: finished"))
            #expect(!view.contains("Button(MacStrings.back"))
            for retired in ["back", "connectionAtStartup", "lockdown", "refreshServiceState"] {
                #expect(!WGEXAccessibility.catalogue.contains { $0.id == "wgex.onboarding.\(retired)" })
            }
        }

        @Test func `setup words never say profile and only the two openers carry an ellipsis`() {
            let buttons = [MacStrings.continueLabel, MacStrings.openSystemSettingsEllipsis, MacStrings.notNow, MacStrings.registerAgain]
            let words = MacOnboardingStep.ordered.flatMap { [$0.title, $0.message] } + buttons + MacStrings.setupCatalogue + [
                MacStrings.backgroundService, MacStrings.importFromFile, MacStrings.pasteFromClipboard, MacStrings.createEmptyTunnel,
            ] + ServiceState.allCases.flatMap { state in [false, true].map { MacOnboardingStep.serviceWord(state: state, running: $0) } }
            for word in words {
                #expect(!word.lowercased().contains("profile"), "\(word)")
                #expect(!word.lowercased().contains("daemon"), "\(word)")
            }
            let openers = [MacStrings.openSystemSettingsEllipsis, MacStrings.importFromFile]
            for word in buttons + MacOnboardingStep.ordered.map(\.title) + [MacStrings.pasteFromClipboard, MacStrings.createEmptyTunnel] {
                #expect(word.hasSuffix("…") == openers.contains(word), "\(word)")
            }
        }

        private func source(_ path: String) throws -> String {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            return try String(contentsOf: root.appending(path: path), encoding: .utf8)
        }
    }
#endif
