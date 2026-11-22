// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation

    /// Owns the sole statistics timer. Hidden or inactive surfaces have no task.
    @MainActor
    public final class MacStatisticsSampler {
        private let sleep: () async throws -> Void
        private let sample: () async -> Void
        private var task: Task<Void, Never>?
        private var eligible = false

        /// Inject the clock and request for deterministic tests. Requests remain serial.
        public init(
            sleep: @escaping () async throws -> Void = { try await Task.sleep(for: .seconds(2)) },
            sample: @escaping () async -> Void,
        ) {
            self.sleep = sleep
            self.sample = sample
        }

        /// Reconciles task lifetime on visibility or tunnel-phase changes.
        public func update(visible: Bool, active: Bool) {
            eligible = visible && active
            guard eligible else {
                task?.cancel()
                return
            }
            guard task == nil else { return }
            task = Task { [weak self, sleep, sample] in
                defer { self?.finished() }
                while !Task.isCancelled {
                    guard self?.eligible == true else { return }
                    await sample()
                    guard !Task.isCancelled else { return }
                    do { try await sleep() } catch { return }
                }
            }
        }

        private func finished() {
            task = nil
            if eligible {
                update(visible: true, active: true)
            }
        }

        deinit { task?.cancel() }
    }
#endif
