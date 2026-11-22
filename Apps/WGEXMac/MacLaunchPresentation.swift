// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit

    /// The launch inputs the decision reads, reduced from the launch Apple event by `MacLoginLaunch.signals(_:)`.
    public struct MacLaunchSignals: Equatable, Sendable {
        /// The event is an open-application event (a plain launch, not open-documents or open-URL).
        public var isOpenApplication: Bool
        /// keyAELaunchedAsLogInItem was present, as a parameter or as the keyAEPropData value or field.
        public var loginItemFlag: Bool
        /// The executable name of the process that sent the event, when the event names one.
        public var sender: String?

        public init(isOpenApplication: Bool, loginItemFlag: Bool, sender: String?) {
            self.isOpenApplication = isOpenApplication; self.loginItemFlag = loginItemFlag; self.sender = sender
        }

        /// The processes that open apps for the login session: login items and windows reopened at login.
        /// They never launch an app at the user's request, so either one marks a login launch on its own.
        public static let loginSessionSenders: Set<String> = ["loginwindow", "backgroundtaskmanagementagent"]

        /// A login launch is an open-application event that carries the login-item flag or comes from the login session.
        /// The flag alone is not trusted to be present: macOS may open a main-app login item without it.
        public var isLoginLaunch: Bool {
            guard isOpenApplication else { return false }
            if loginItemFlag {
                return true
            }
            guard let sender else { return false }
            return Self.loginSessionSenders.contains(sender.lowercased())
        }
    }

    /// What reaches the launch decision: the launch event (nil while AppKit has not made it current yet), or a reopen.
    public enum MacLaunchRequest: Equatable, Sendable {
        case launch(MacLaunchSignals?)
        case reopen(hasVisibleWindows: Bool)
    }

    /// The outcome of one launch request: the next presentation, the Dock state and whether the main window opens.
    public struct MacLaunchDecision: Equatable, Sendable {
        public var presentation: MacLaunchPresentation
        public var hidesDock: Bool
        public var opensWindow: Bool
    }

    /// How the app presents itself after launch: a login launch stays in the menu bar with no Dock icon and no
    /// main window until the user opens the window (parity X3, official AppDelegate `.prohibited` start).
    public struct MacLaunchPresentation: Equatable, Sendable {
        /// True from a login launch until the user opens the window or reactivates the app, and while the
        /// launch kind is still undecided.
        public private(set) var silent: Bool
        /// False until the launch event decided the kind (or the user asked for the window first).
        public private(set) var settled: Bool

        public init(isLoginLaunch: Bool) {
            silent = isLoginLaunch
            settled = true
        }

        private init(silent: Bool, settled: Bool) {
            self.silent = silent; self.settled = settled
        }

        /// Before the delegate has seen any launch event: nothing hidden, nothing decided.
        public static let unlaunched = MacLaunchPresentation(silent: false, settled: false)
        /// No launch event was current yet: stay silent (no window, no Dock icon) until one decides.
        public static let awaitingEvent = MacLaunchPresentation(silent: true, settled: false)

        /// The pure launch decision. A launch event decides once; a missing event keeps the launch silent and
        /// undecided; a later launch event never re-decides a settled launch. A reopen is the user asking for the
        /// window: it ends a silent launch and opens the window only when none is visible.
        public static func decide(
            _ request: MacLaunchRequest, from current: MacLaunchPresentation, hideDockIcon: Bool,
        ) -> MacLaunchDecision {
            switch request {
            case let .launch(signals):
                guard !current.settled else {
                    let hidesDock = current.hidesDock(hideDockIcon: hideDockIcon)
                    return MacLaunchDecision(presentation: current, hidesDock: hidesDock, opensWindow: false)
                }
                guard let signals else {
                    return MacLaunchDecision(presentation: .awaitingEvent, hidesDock: true, opensWindow: false)
                }
                let login = signals.isLoginLaunch
                return MacLaunchDecision(
                    presentation: MacLaunchPresentation(isLoginLaunch: login),
                    hidesDock: login || hideDockIcon,
                    opensWindow: !login,
                )
            case let .reopen(hasVisibleWindows):
                var next = current
                next.windowRequested()
                return MacLaunchDecision(presentation: next, hidesDock: hideDockIcon, opensWindow: !hasVisibleWindows)
            }
        }

        /// The Dock follows Hide Dock icon, and a silent launch hides it regardless of that preference.
        public func hidesDock(hideDockIcon: Bool) -> Bool {
            silent || hideDockIcon
        }

        public func activationPolicy(hideDockIcon: Bool) -> NSApplication.ActivationPolicy {
            hidesDock(hideDockIcon: hideDockIcon) ? .accessory : .regular
        }

        /// The menu's Open, a reopen or any other request for the window ends the silent launch and settles an
        /// undecided one. Returns whether the presentation changed.
        @discardableResult
        public mutating func windowRequested() -> Bool {
            settled = true
            guard silent else { return false }
            silent = false
            return true
        }
    }
#endif
