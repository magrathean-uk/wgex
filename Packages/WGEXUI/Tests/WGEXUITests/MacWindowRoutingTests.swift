// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacWindowRoutingTests {
        private func model(_ root: URL) -> MacAppModel {
            MacAppModel(
                arguments: ["-WGEXFakeBackend"], container: root,
                fakeServiceFactory: { FakeServiceController() }, applyDockPolicy: { _ in },
            )
        }

        @Test(arguments: MacWindowEntryPoint.allCases)
        func `every explicit entry uses the main window open action`(_ entry: MacWindowEntryPoint) {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            let tunnel = TunnelProfile(name: "Home")
            app.shell.profiles = [tunnel]
            app.shell.selectedProfileID = tunnel.id
            app.shell.windowSelection = .settings(.protection)
            app.beginLaunch(isLoginLaunch: true)
            var opens = 0
            app.requestWindow(entry) { opens += 1 }
            #expect(opens == 1)
            #expect(!app.launchPresentation.silent)
            #expect(app.shell.selectedProfileID == tunnel.id)
            switch entry {
            case .about: #expect(app.shell.windowSelection == .settings(.about))
            case .settings: #expect(app.shell.windowSelection == .settings(.general))
            case .reopen: #expect(app.shell.windowSelection == .settings(.protection))
            case .setup:
                #expect(!app.shell.showsSettings)
                #expect(app.shell.showsOnboarding)
                #expect(app.shell.onboardingStep == .welcome)
            case .manageTunnels, .importTunnel: #expect(!app.shell.showsSettings)
            }
            app.presentInitialOnboarding()
            #expect(app.shell.showsOnboarding == (entry == .setup))
        }

        @Test func `menu About and Manage dispatch through the real controller without starting a status item`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            app.beginLaunch(isLoginLaunch: true)
            var opens = 0
            app.installWindowOpener { opens += 1 }
            let controller = MacStatusItemController(model: app, activate: {})
            controller.perform(.about)
            #expect(opens == 1)
            #expect(app.shell.windowSelection == .settings(.about))
            #expect(!app.launchPresentation.silent)
            controller.perform(.manage)
            #expect(opens == 2)
            #expect(!app.shell.showsSettings)
            controller.perform(.open)
            #expect(opens == 3)
            #expect(!app.shell.showsSettings)
            #expect(app.pendingWindowOpens == 0)
        }

        @Test func `opens queued before a live view installs the action wait for it and run once`() async {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            app.beginLaunch(isLoginLaunch: false)
            #expect(app.pendingWindowOpens == 1)
            // The status item observes the queue from did-finish-launching; with no action installed nothing is used up.
            app.dispatchPendingWindowOpens()
            let controller = MacStatusItemController(model: app, activate: {})
            controller.perform(.about)
            #expect(!app.canOpenWindow)
            #expect(app.pendingWindowOpens == 2)
            var opens = 0
            app.installWindowOpener { opens += 1 }
            #expect(opens == 0, "No open runs inside the installing view update")
            for _ in 0 ..< 20 where app.pendingWindowOpens > 0 {
                await Task.yield()
            }
            #expect(opens == 2)
            #expect(app.pendingWindowOpens == 0)
            #expect(app.shell.windowSelection == .settings(.about))
            // Reinstalling from a rebuilt command view replaces the action without replaying anything.
            var replaced = 0
            app.installWindowOpener { replaced += 1 }
            app.dispatchPendingWindowOpens()
            controller.perform(.manage)
            #expect(opens == 2)
            #expect(replaced == 1)
        }

        @Test func `launch order does not matter between the launch decision and the action install`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            var opens = 0
            app.installWindowOpener { opens += 1 }
            app.beginLaunch(isLoginLaunch: false)
            #expect(opens == 0)
            // The status item's first observation pass at did-finish-launching performs the queued launch open.
            app.dispatchPendingWindowOpens()
            #expect(opens == 1)
            let login = model(root)
            var loginOpens = 0
            login.installWindowOpener { loginOpens += 1 }
            login.beginLaunch(isLoginLaunch: true)
            login.dispatchPendingWindowOpens()
            #expect(loginOpens == 0)
        }

        @Test func `setup can be dismissed and requested again without opening a second scene`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            var opens = 0
            app.requestWindow(.setup) { opens += 1 }
            app.shell.showsOnboarding = false
            app.shell.revisit(.addTunnel)
            app.requestWindow(.setup) { opens += 1 }
            #expect(opens == 2)
            #expect(app.shell.showsOnboarding)
            #expect(app.shell.onboardingStep == .welcome)
            app.requestWindow(.about) { opens += 1 }
            #expect(!app.shell.showsOnboarding)
            #expect(app.shell.windowSelection == .settings(.about))
        }

        @Test func `initial onboarding respects login launch completion and explicit destinations`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            app.beginLaunch(isLoginLaunch: true)
            app.presentInitialOnboarding()
            #expect(!app.shell.showsOnboarding)
            app.beginLaunch(isLoginLaunch: false)
            app.shell.preferences.onboardingComplete = true
            app.presentInitialOnboarding()
            #expect(!app.shell.showsOnboarding)
            app.shell.preferences.onboardingComplete = false
            app.presentInitialOnboarding()
            #expect(app.shell.showsOnboarding)
        }

        @Test func `an import received by the existing scene is not displaced by initial setup`() {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            app.beginLaunch(isLoginLaunch: true)
            app.shell.windowSelection = .settings(.general)
            app.routeWindow(.importTunnel)
            app.presentInitialOnboarding()
            #expect(!app.launchPresentation.silent)
            #expect(!app.shell.showsSettings)
            #expect(!app.shell.showsOnboarding)
        }

        @Test(arguments: [false, true])
        func `Dock reopen retains the current page and queues only a missing main window`(visible: Bool) {
            let root = MacWorkflowTests.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let app = model(root)
            app.beginLaunch(isLoginLaunch: true)
            app.shell.windowSelection = .settings(.diagnostics)
            let delegate = MacApplicationDelegate(currentEvent: { nil })
            delegate.reopen = app.reopenRequested
            _ = delegate.applicationShouldHandleReopen(.shared, hasVisibleWindows: visible)
            #expect(app.shell.windowSelection == .settings(.diagnostics))
            #expect(!app.launchPresentation.silent)
            var opens = 0
            app.dispatchPendingWindowOpens { opens += 1 }
            #expect(opens == (visible ? 0 : 1))
            app.dispatchPendingWindowOpens { opens += 1 }
            #expect(opens == (visible ? 0 : 1))
        }
    }
#endif
