// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation

    /// Finishes the preference writer before termination, bounded to one second.
    @MainActor
    public final class MacTerminationFlush {
        private let clock: MacUIClock
        private var writeTask: Task<Void, Never>?
        private var capTask: Task<Void, Never>?
        private var reply: (() -> Void)?

        /// Tests inject the cap clock; application termination uses the system clock.
        public init(clock: MacUIClock = MacUIClock()) {
            self.clock = clock
        }

        /// Replies once when the write finishes or the cap expires; never blocks the main actor.
        public func start(flush: @escaping () async -> Void, reply: @escaping () -> Void) {
            guard self.reply == nil else { return }
            self.reply = reply
            writeTask = Task { [weak self] in
                await flush()
                self?.finish()
            }
            capTask = Task { [weak self, clock] in
                do { try await clock.sleep(1) } catch { return }
                self?.finish()
            }
        }

        private func finish() {
            guard let reply else { return }
            self.reply = nil
            writeTask?.cancel()
            capTask?.cancel()
            reply()
        }
    }
#endif
