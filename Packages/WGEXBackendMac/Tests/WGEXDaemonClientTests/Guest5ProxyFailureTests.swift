// SPDX-License-Identifier: MIT
#if os(macOS)
    import Dispatch
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    @testable import WGEXDaemonProtocol

    /// Models Foundation invoking an unannotated, immutable callback once on its own queue.
    private final class LegacyProxyFailure: @unchecked Sendable {
        let handler: (any Error) -> Void
        init(_ handler: @escaping (any Error) -> Void) {
            self.handler = handler
        }

        func fire() {
            handler(DaemonError.disconnected)
        }
    }

    @Suite(.timeLimit(.minutes(1)))
    private struct Guest5ProxyFailureTests {
        @Test
        func `U8 proxy failure from a non actor queue makes doctor report daemonUnavailable`() async {
            let transport = NSXPCClientTransport(proxyLookup: { handler in
                let callback = LegacyProxyFailure(handler)
                DispatchQueue.global().async { callback.fire() }
                return SilentDaemonProxy()
            })
            let client = DaemonClient(transport: transport, clientVersion: "test", clientBuild: 10)
            let result = await WGEXCLICore(client: client, service: InertGuest5Service(), plistExists: { false }).run(["doctor", "--json"])
            #expect(result.exitCode == 1)
            #expect(result.output.contains("daemonUnavailable"))
            await client.disconnect()
        }
    }

    private final class SilentDaemonProxy: NSObject, WGEXDaemonXPC {
        func send(_: Data, reply _: @escaping @Sendable (Data) -> Void) {}
        func start(_: Data, secrets _: Data, reply _: @escaping @Sendable (Data) -> Void) {}
        func setStartBeforeLogin(_: Data, secrets _: Data, reply _: @escaping @Sendable (Data) -> Void) {}
        func subscribe(_: Data, reply _: @escaping @Sendable (Data) -> Void) {}
        func armOnDemand(_: Data, secrets _: Data, reply _: @escaping @Sendable (Data) -> Void) {}
    }

    private struct InertGuest5Service: ServiceControlling {
        var state: AsyncStream<ServiceState> {
            AsyncStream { $0.finish() }
        }

        func register() async throws(ServiceError) {
            throw .hostGuard
        }

        func unregister() async throws(ServiceError) {
            throw .hostGuard
        }

        func openApproval() {}
    }
#endif
