// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation

    /// Injectable wall time and cancellable sleeps for display, sampling and semantic deadlines.
    @MainActor
    public struct MacUIClock {
        /// Current wall time.
        public let now: () -> Date
        /// Waits for an interval; cancellation must end the wait.
        public let sleep: (TimeInterval) async throws -> Void

        /// Defaults to the system clock; tests can advance all UI work without real delays.
        public init(
            now: @escaping () -> Date = { Date() },
            sleep: @escaping (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) },
        ) {
            self.now = now
            self.sleep = sleep
        }
    }
#endif
