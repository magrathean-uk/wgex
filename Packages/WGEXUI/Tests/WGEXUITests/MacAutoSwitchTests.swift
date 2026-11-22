// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    private struct SwitchFailure: Error {}

    /// Logs every call in order; stop and start can be told to fail.
    private final class OrderedBackend: TunnelBackend {
        let log = Mutex<[String]>([])
        let failStart = Mutex(false)
        var capabilities: BackendCapabilities {
            [.killSwitch]
        }

        func install(_: TunnelProfile) async throws(TunnelError) {
            log.withLock { $0.append("install") }
        }

        func remove(_: UUID, purgeSecrets _: Bool) async throws(TunnelError) {}
        func start(_: UUID, transport _: TransportID?) async throws(TunnelError) {
            log.withLock { $0.append("start") }
            if failStart.withLock({ $0 }) {
                throw .backendUnavailable
            }
        }

        func stop(_: UUID) async throws(TunnelError) {
            log.withLock { $0.append("stop") }
        }

        func statusUpdates() -> AsyncStream<TunnelStatus> {
            AsyncStream { $0.finish() }
        }

        func statistics() async throws(TunnelError) -> TunnelStatistics {
            throw .backendUnavailable
        }
    }

    @MainActor
    @Suite("M02-T10 auto-switch", .timeLimit(.minutes(1)))
    package struct MacAutoSwitchTests {
        private let first = TunnelProfile(name: "First")
        private let second = TunnelProfile(name: "Second")

        private func make(_ backend: OrderedBackend, stop: @escaping () async throws -> Void) -> MacShellModel {
            var status = TunnelStatus(
                phase: .active(Generation(rawValue: 1)),
                protection: .protected,
                transport: nil,
                health: .idle,
                recentEvents: [],
            )
            status.activeProfileID = first.id
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: FakeServiceController(initial: .enabled), simulated: false,
            ), profiles: [first, second], status: status)
            model.receiveService(.enabled)
            model.daemonHooks.stopCurrent = stop
            model.selectedProfileID = second.id
            return model
        }

        @Test package func `stop completes before the next tunnel is started`() async {
            let backend = OrderedBackend()
            let model = make(backend) {
                backend.log.withLock { $0.append("stop-begin") }
                for _ in 0 ..< 20 {
                    await Task.yield()
                }
                backend.log.withLock { $0.append("stop-end") }
            }
            await model.toggleConnection()
            #expect(backend.log.withLock { $0 } == ["stop-begin", "stop-end", "install", "start"])
            #expect(model.operationMessage == nil)
        }

        @Test package func `a failed stop starts nothing and leaves the active tunnel`() async {
            let backend = OrderedBackend()
            let model = make(backend) { throw SwitchFailure() }
            await model.toggleConnection()
            #expect(backend.log.withLock { $0 }.isEmpty)
            #expect(model.activeProfileID == first.id)
        }

        @Test package func `a failed start after stop reports the error and does not restart the old tunnel`() async {
            let backend = OrderedBackend()
            backend.failStart.withLock { $0 = true }
            let model = make(backend) { backend.log.withLock { $0.append("stop") } }
            await model.toggleConnection()
            #expect(backend.log.withLock { $0 } == ["stop", "install", "start"])
            #expect(model.operationMessage != nil)
        }

        @Test package func `switching never surfaces another tunnel active`() async {
            let backend = OrderedBackend()
            let model = make(backend) {}
            await model.toggleConnection()
            #expect(model.operationMessage != MacErrorCopy(tunnel: .anotherTunnelActive).message)
        }
    }
#endif
