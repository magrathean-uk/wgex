// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Carbon
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    @MainActor
    private final class ActivationRecorder {
        var flags: [Bool] = []
    }

    @MainActor
    private struct MacLoginLaunchTests {
        @Test func `only an explicit login launch starts the configured login profile`() async throws {
            let backend = FakeTunnelBackend(clock: FakeClock())
            var profile = try EditorFixtures.profile()
            profile.macOptions = MacStartupOption.login.profileOptions
            let service = FakeServiceController()
            let model = MacShellModel(dependencies: .init(
                backend: backend,
                service: service,
                simulated: true,
                operations: .init(refreshDaemon: { true }),
            ), profiles: [profile])
            await model.connectAtLogin()
            #expect(backend.calls.isEmpty)
            service.transition(to: .enabled)
            await model.refreshService()
            await model.connectAtLogin()
            #expect(backend.calls.contains(.install(profile.id)))
            #expect(backend.calls.contains(.start(profile.id, transport: nil)))
        }

        @Test func `login Apple event detection rejects ordinary launches`() {
            let event = NSAppleEventDescriptor.appleEvent(
                withEventClass: kCoreEventClass,
                eventID: kAEOpenApplication,
                targetDescriptor: nil,
                returnID: AEReturnID(kAutoGenerateReturnID),
                transactionID: AETransactionID(kAnyTransactionID),
            )
            #expect(!MacLoginLaunch.isLoginLaunch(event))
            event.setParam(NSAppleEventDescriptor(enumCode: keyAELaunchedAsLogInItem), forKeyword: keyAEPropData)
            #expect(MacLoginLaunch.isLoginLaunch(event))
            #expect(!MacLoginLaunch.isLoginLaunch(nil))
        }

        // MARK: Silent login launch (parity X3)

        @Test func `a login launch hides the Dock and shows no window even when the preference shows the Dock`() {
            let presentation = MacLaunchPresentation(isLoginLaunch: true)
            #expect(presentation.silent)
            #expect(presentation.hidesDock(hideDockIcon: false))
            #expect(presentation.activationPolicy(hideDockIcon: false) == .accessory)
            #expect(presentation.activationPolicy(hideDockIcon: true) == .accessory)
        }

        @Test func `an ordinary launch follows the Hide Dock icon preference`() {
            let presentation = MacLaunchPresentation(isLoginLaunch: false)
            #expect(!presentation.silent)
            #expect(presentation.activationPolicy(hideDockIcon: false) == .regular)
            #expect(presentation.activationPolicy(hideDockIcon: true) == .accessory)
        }

        @Test func `opening the window ends the silent launch and restores the Dock unless it is hidden`() {
            var presentation = MacLaunchPresentation(isLoginLaunch: true)
            let changed = presentation.windowRequested()
            #expect(changed)
            #expect(!presentation.silent)
            #expect(presentation.activationPolicy(hideDockIcon: false) == .regular)
            #expect(presentation.activationPolicy(hideDockIcon: true) == .accessory)
            let again = presentation.windowRequested()
            #expect(!again)
            var ordinary = MacLaunchPresentation(isLoginLaunch: false)
            let ordinaryChanged = ordinary.windowRequested()
            #expect(!ordinaryChanged)
        }

        @Test func `the model applies accessory at a login launch, keeps it through the load, restores on open`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            model.beginLaunch(isLoginLaunch: true)
            #expect(model.launchPresentation.silent)
            #expect(policies == [true])
            await model.start()
            defer { model.stopObserving() }
            #expect(policies.last == true)
            model.windowRequested()
            #expect(!model.launchPresentation.silent)
            #expect(policies.last == false)
            let count = policies.count
            model.windowRequested()
            #expect(policies.count == count)
        }

        @Test func `an ordinary launch never hides the Dock and a hidden-Dock preference survives opening the window`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            model.beginLaunch(isLoginLaunch: false)
            #expect(policies.isEmpty)
            await model.start()
            defer { model.stopObserving() }
            #expect(policies == [false])

            var hidden: [Bool] = []
            let hiding = try Self.model(hideDockIcon: true) { hidden.append($0) }
            hiding.beginLaunch(isLoginLaunch: true)
            await hiding.start()
            defer { hiding.stopObserving() }
            hiding.windowRequested()
            #expect(!hidden.contains(false))
            #expect(!hiding.launchPresentation.silent)
        }

        @Test func `the launch kind is decided at will-finish-launching from the Apple event, before any start`() throws {
            var policies: [Bool] = []
            let login = try Self.model(hideDockIcon: false) { policies.append($0) }
            #expect(login.willFinishLaunching(event: Self.openEvent(login: true)))
            #expect(login.launchPresentation.silent)
            #expect(policies == [true])
            #expect(login.pendingWindowOpens == 0)

            var ordinaryPolicies: [Bool] = []
            let ordinary = try Self.model(hideDockIcon: false) { ordinaryPolicies.append($0) }
            #expect(!ordinary.willFinishLaunching(event: Self.openEvent(login: false)))
            #expect(!ordinary.launchPresentation.silent)
            #expect(ordinaryPolicies.isEmpty)
            let missing = try Self.model(hideDockIcon: false) { _ in }
            #expect(!missing.willFinishLaunching(event: nil))
        }

        @Test func `an ordinary launch requests the main window exactly once`() throws {
            let model = try Self.model(hideDockIcon: false) { _ in }
            model.willFinishLaunching(event: Self.openEvent(login: false))
            #expect(model.takePendingWindowOpen())
            #expect(!model.takePendingWindowOpen())
            model.windowRequested()
            #expect(!model.takePendingWindowOpen())
        }

        @Test func `a login launch requests the main window zero times until the user asks`() throws {
            let model = try Self.model(hideDockIcon: false) { _ in }
            model.willFinishLaunching(event: Self.openEvent(login: true))
            #expect(!model.takePendingWindowOpen())
            #expect(!model.takePendingWindowOpen())
            model.reopenRequested(hasVisibleWindows: true)
            #expect(!model.launchPresentation.silent)
            #expect(!model.takePendingWindowOpen())
            let again = try Self.model(hideDockIcon: false) { _ in }
            again.willFinishLaunching(event: Self.openEvent(login: true))
            again.reopenRequested(hasVisibleWindows: false)
            #expect(again.takePendingWindowOpen())
            #expect(!again.takePendingWindowOpen())
        }

        // MARK: Production delegate and open dispatch

        @Test func `the delegate decides a login launch at will-finish-launching alone`() throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let delegate = Self.delegate(model: model, event: Self.openEvent(login: true))
            delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            #expect(model.launchPresentation.silent)
            #expect(policies == [true])
            #expect(model.pendingWindowOpens == 0)
        }

        @Test func `the delegate decides an ordinary launch at will-finish-launching with one queued open`() throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let delegate = Self.delegate(model: model, event: Self.openEvent(login: false))
            delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            #expect(!model.launchPresentation.silent)
            #expect(policies.isEmpty)
            #expect(model.pendingWindowOpens == 1)
        }

        @Test func `did-finish-launching alone settles a launch that will-finish left undecided`() throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let delegate = Self.delegate(model: model, event: Self.openEvent(login: true))
            delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(model.launchPresentation.silent)
            #expect(model.launchedAtLogin)
            #expect(policies == [true])
            #expect(model.pendingWindowOpens == 0)
        }
    }

    @MainActor
    private extension MacLoginLaunchTests {
        // MARK: Production delegate across both launch stages (event current only at did-finish-launching)

        @Test(arguments: [false, true])
        func `a login event first current at did-finish keeps the launch silent and activates as login`(
            hideDockIcon: Bool,
        ) async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: hideDockIcon) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [nil, Self.openEvent(login: true)])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            #expect(model.launchPresentation.silent)
            #expect(model.pendingWindowOpens == 0)
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(model.launchPresentation.silent)
            #expect(model.launchedAtLogin)
            #expect(!model.takePendingWindowOpen())
            #expect(policies == [true])
            await rig.coordinator.didFinishLaunching(isLoginLaunch: false).value
            #expect(rig.activations() == [true])
        }

        @Test(arguments: [false, true])
        func `an ordinary event first current at did-finish opens the window once and keeps the Dock preference`(
            hideDockIcon: Bool,
        ) async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: hideDockIcon) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [nil, Self.openEvent(login: false)])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(!model.launchPresentation.silent)
            #expect(!model.launchedAtLogin)
            var opens = 0
            model.dispatchPendingWindowOpens { opens += 1 }
            model.dispatchPendingWindowOpens { opens += 1 }
            #expect(opens == 1)
            // Silent while undecided; the Dock is shown only once the Hide Dock icon preference is known.
            #expect(policies == [true])
            await rig.coordinator.didFinishLaunching(isLoginLaunch: true).value
            #expect(rig.activations() == [false])
            await model.start()
            defer { model.stopObserving() }
            #expect(policies.last == hideDockIcon)
            #expect(policies.contains(false) == !hideDockIcon)
        }

        @Test func `no event at either stage is an ordinary launch with one window open`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [nil, nil])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(!model.launchPresentation.silent)
            #expect(model.pendingWindowOpens == 1)
            #expect(policies == [true])
            await rig.coordinator.didFinishLaunching(isLoginLaunch: true).value
            #expect(rig.activations() == [false])
            await model.start()
            defer { model.stopObserving() }
            #expect(policies == [true, false])
        }

        @Test func `a launch decided at will-finish is not re-decided by the did-finish event`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [Self.openEvent(login: true), Self.openEvent(login: false)])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(model.launchPresentation.silent)
            #expect(model.pendingWindowOpens == 0)
            #expect(policies == [true])
            await rig.coordinator.didFinishLaunching(isLoginLaunch: false).value
            #expect(rig.activations() == [true])
            await model.start()
            defer { model.stopObserving() }
            #expect(!policies.contains(false))
            // The user then asks for the window: the Dock comes back and the login decision stays recorded.
            #expect(rig.delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false))
            #expect(!model.launchPresentation.silent)
            #expect(model.launchedAtLogin)
            #expect(model.pendingWindowOpens == 1)
            #expect(policies.last == false)
        }

        @Test func `a reopen while the launch is undecided settles it as ordinary before did-finish`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: false) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [nil, Self.openEvent(login: true)])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            #expect(rig.delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false))
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            #expect(!model.launchPresentation.silent)
            #expect(model.pendingWindowOpens == 1)
            // The Dock waits for the preference load before it shows.
            #expect(policies == [true])
            await model.start()
            defer { model.stopObserving() }
            #expect(policies == [true, false])
        }

        @Test func `a Hide Dock icon preference keeps the Dock hidden when the window opens after a login launch`() async throws {
            var policies: [Bool] = []
            let model = try Self.model(hideDockIcon: true) { policies.append($0) }
            let rig = Self.stagedDelegate(model: model, events: [nil, Self.openEvent(login: true)])
            rig.delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            rig.delegate.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
            await model.start()
            defer { model.stopObserving() }
            model.windowRequested()
            #expect(!model.launchPresentation.silent)
            #expect(!policies.isEmpty)
            #expect(!policies.contains(false))
        }

        @Test func `the delegate reopen reaches the model and queues one open only without a visible window`() throws {
            let model = try Self.model(hideDockIcon: false) { _ in }
            let delegate = Self.delegate(model: model, event: Self.openEvent(login: true))
            delegate.applicationWillFinishLaunching(Notification(name: NSApplication.willFinishLaunchingNotification))
            #expect(delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: true))
            #expect(model.pendingWindowOpens == 0)
            #expect(!model.launchPresentation.silent)
            #expect(delegate.applicationShouldHandleReopen(NSApplication.shared, hasVisibleWindows: false))
            #expect(model.pendingWindowOpens == 1)
        }

        @Test func `the dispatch opens the window once for an ordinary launch, never for a login launch`() throws {
            let ordinary = try Self.model(hideDockIcon: false) { _ in }
            ordinary.willFinishLaunching(event: Self.openEvent(login: false))
            var ordinaryOpens = 0
            ordinary.dispatchPendingWindowOpens { ordinaryOpens += 1 }
            ordinary.dispatchPendingWindowOpens { ordinaryOpens += 1 }
            #expect(ordinaryOpens == 1)

            let login = try Self.model(hideDockIcon: false) { _ in }
            login.willFinishLaunching(event: Self.openEvent(login: true))
            var loginOpens = 0
            login.dispatchPendingWindowOpens { loginOpens += 1 }
            #expect(loginOpens == 0)
        }

        @Test func `the dispatch opens once for a reopen with no visible window and not with one`() throws {
            let model = try Self.model(hideDockIcon: false) { _ in }
            model.willFinishLaunching(event: Self.openEvent(login: true))
            var opens = 0
            model.reopenRequested(hasVisibleWindows: true)
            model.dispatchPendingWindowOpens { opens += 1 }
            #expect(opens == 0)
            model.reopenRequested(hasVisibleWindows: false)
            model.dispatchPendingWindowOpens { opens += 1 }
            #expect(opens == 1)
            #expect(model.pendingWindowOpens == 0)
        }

        private static func delegate(model: MacAppModel, event: NSAppleEventDescriptor?) -> MacApplicationDelegate {
            let delegate = MacApplicationDelegate(currentEvent: { event })
            delegate.launch = { model.willFinishLaunching(event: $0) }
            delegate.finishLaunch = { model.didFinishLaunching(event: $0) }
            delegate.reopen = { model.reopenRequested(hasVisibleWindows: $0) }
            return delegate
        }

        /// The delegate wired as WGEXMacApp wires it, serving one event per launch stage and recording the
        /// login flag the activation pass receives.
        private static func stagedDelegate(
            model: MacAppModel, events: [NSAppleEventDescriptor?],
        ) -> (delegate: MacApplicationDelegate, coordinator: MacAppActivationCoordinator, activations: () -> [Bool]) {
            var queue = events
            let delegate = MacApplicationDelegate(currentEvent: { queue.isEmpty ? nil : queue.removeFirst() })
            delegate.launch = { model.willFinishLaunching(event: $0) }
            delegate.finishLaunch = { model.didFinishLaunching(event: $0) }
            delegate.reopen = { model.reopenRequested(hasVisibleWindows: $0) }
            let recorder = ActivationRecorder()
            let coordinator = MacAppActivationCoordinator(isActive: { false }) { recorder.flags.append($0) }
            delegate.activation = coordinator
            return (delegate, coordinator, { recorder.flags })
        }

        private static func openEvent(login: Bool) -> NSAppleEventDescriptor {
            let event = NSAppleEventDescriptor.appleEvent(
                withEventClass: kCoreEventClass,
                eventID: kAEOpenApplication,
                targetDescriptor: nil,
                returnID: AEReturnID(kAutoGenerateReturnID),
                transactionID: AETransactionID(kAnyTransactionID),
            )
            if login {
                event.setParam(NSAppleEventDescriptor(enumCode: keyAELaunchedAsLogInItem), forKeyword: keyAEPropData)
            }
            return event
        }

        private static func model(hideDockIcon: Bool, applyDockPolicy: @escaping (Bool) -> Void) throws -> MacAppModel {
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("wgex-login-\(UUID().uuidString)")
            var preferences = MacPreferences()
            preferences.hideDockIcon = hideDockIcon
            return MacAppModel(
                arguments: ["-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { WGEXTesting.FakeServiceController(initial: .enabled) },
                preferencesLoader: { preferences },
                applyDockPolicy: applyDockPolicy,
            )
        }
    }
#endif
