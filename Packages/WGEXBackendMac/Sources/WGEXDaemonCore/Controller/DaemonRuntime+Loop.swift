// SPDX-License-Identifier: MIT
import WGEXCore

public extension DaemonRuntime {
    /// The verification loop waits for lifecycle retries; status reporting has its own dispatcher timer.
    struct LoopPorts: Sendable {
        package let retryLifecycle: @Sendable () async -> Void
        package let tick: @Sendable () async throws -> Void
        package let failure: @Sendable (any Error) -> Void

        /// Supplies effects without acquiring any host resource.
        public init(
            retryLifecycle: @escaping @Sendable () async -> Void,
            tick: @escaping @Sendable () async throws -> Void,
            failure: @escaping @Sendable (any Error) -> Void,
        ) {
            self.retryLifecycle = retryLifecycle; self.tick = tick; self.failure = failure
        }
    }

    /// Drives five-second verification ticks, retaining the M1-05 retry-before-tick ordering.
    func runMainLoop(ports: LoopPorts) async {
        while !Task.isCancelled {
            do { try await sleepForTick(); try Task.checkCancellation() }
            catch { return }
            if isRecovering {
                continue
            }
            await ports.retryLifecycle()
            guard !Task.isCancelled else { return }
            do { try await ports.tick() }
            catch { ports.failure(error) }
        }
    }

    /// SIGTERM cannot complete until blocking shutdown succeeds; failures retry every five seconds.
    func terminate(
        refreshUnderlay: @escaping @Sendable () async -> Void,
        waiting: @escaping @Sendable () -> Void,
    ) async {
        while true {
            await refreshUnderlay()
            do { try await shutdown(); return }
            catch {
                waiting()
                await waitForShutdownRetry()
            }
        }
    }
}
