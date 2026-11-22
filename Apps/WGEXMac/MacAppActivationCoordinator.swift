// SPDX-License-Identifier: MIT

#if os(macOS)
    /// Owns the launch pass independently of whether a foreground activation is delivered.
    @MainActor
    public final class MacAppActivationCoordinator {
        private let isActive: () -> Bool
        private let activation: (Bool) async -> Void
        private var launchTask: Task<Void, Never>?
        private var skipMatchingActivation = false

        /// The activity probe is read-only; tests supply recording operations and fixed activity.
        public init(isActive: @escaping () -> Bool, activation: @escaping (Bool) async -> Void) {
            self.isActive = isActive; self.activation = activation
        }

        /// Launch consumes the login flag once, including accessory/Dock-hidden login launches.
        @discardableResult
        public func didFinishLaunching(isLoginLaunch: Bool) -> Task<Void, Never> {
            if let launchTask {
                return launchTask
            }
            skipMatchingActivation = true
            let task = Task {
                await activation(isLoginLaunch)
                // A background launch may never activate; its later first user activation still needs a refresh.
                if !isActive() {
                    skipMatchingActivation = false
                }
            }
            launchTask = task
            return task
        }

        /// Coalesces the initial matching notification; subsequent activations never reuse the login flag.
        @discardableResult
        public func didBecomeActive() -> Task<Void, Never>? {
            guard launchTask != nil else { return nil }
            if skipMatchingActivation {
                skipMatchingActivation = false
                return nil
            }
            return Task { await activation(false) }
        }

        /// Returning from another app must refresh even if launch supplied no matching active notification.
        public func didResignActive() {
            skipMatchingActivation = false
        }
    }
#endif
