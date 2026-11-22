// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import WGEXUI

    /// Owns launch/activation and the bounded preference flush for every termination route.
    /// The launch Apple event source and the launch and reopen decisions are injected so tests drive the real type.
    @MainActor
    public final class MacApplicationDelegate: NSObject, NSApplicationDelegate {
        public var flush: () async -> Void = {}
        public var statusItem: MacStatusItemController?
        public var activation: MacAppActivationCoordinator?
        public var launch: (NSAppleEventDescriptor?) -> Bool = { _ in false }
        /// Settles a launch whose event was not current at will-finish-launching; returns whether it is a login launch.
        public var finishLaunch: (NSAppleEventDescriptor?) -> Bool = { _ in false }
        public var reopen: (Bool) -> Void = { _ in }
        private let currentEvent: () -> NSAppleEventDescriptor?
        private var isLoginLaunch = false
        private let termination = MacTerminationFlush()

        public init(currentEvent: @escaping () -> NSAppleEventDescriptor?) {
            self.currentEvent = currentEvent
            super.init()
        }

        /// The SwiftUI adaptor builds the delegate with the system's current Apple event.
        override public convenience init() {
            self.init(currentEvent: { NSAppleEventManager.shared().currentAppleEvent })
        }

        /// The launch kind is decided here when the launch event is already current, before any window is presented.
        /// Without one the launch stays silent (no window, no Dock icon) until did-finish-launching decides.
        public func applicationWillFinishLaunching(_: Notification) {
            let event = currentEvent()
            isLoginLaunch = launch(event)
            MacLoginLaunch.logLaunchEvent(stage: "will-finish", event: event, isLoginLaunch: isLoginLaunch)
        }

        /// AppKit makes the open-application event current while it posts did-finish-launching, so an undecided launch
        /// is settled here; then the activation pass runs once with the final kind.
        public func applicationDidFinishLaunching(_ notification: Notification) {
            let event = currentEvent()
            isLoginLaunch = finishLaunch(event) || isLoginLaunch
            MacLoginLaunch.logLaunchEvent(
                stage: "did-finish", event: event,
                isDefaultLaunch: notification.userInfo?[NSApplication.launchIsDefaultUserInfoKey] as? Bool,
                isLoginLaunch: isLoginLaunch,
            )
            statusItem?.start()
            activation?.didFinishLaunching(isLoginLaunch: isLoginLaunch)
        }

        /// Launching the app again (Finder, Spotlight) is the user asking for the window after a silent login launch.
        public func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows: Bool) -> Bool {
            reopen(hasVisibleWindows)
            return true
        }

        public func applicationDidBecomeActive(_: Notification) {
            activation?.didBecomeActive()
        }

        public func applicationDidResignActive(_: Notification) {
            activation?.didResignActive()
        }

        public func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
            termination.start(flush: flush) { sender.reply(toApplicationShouldTerminate: true) }
            return .terminateLater
        }
    }
#endif
