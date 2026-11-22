// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct CutoverDispatcherTests {
    @Test(arguments: [60, 600, 3600, 59, 3601])
    func `cutover validates the bounded window`(_ seconds: Int) async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let transport = try await handshaken(dispatcher)
        let request = Request.startCutover(profileID: service.profile, confirmWithin: seconds, hasSecrets: false)
        let reply = try await call(transport, request)
        #expect(reply == ((60 ... 3600).contains(seconds) ? .ok : .error(.malformedMessage)))
    }

    @Test(arguments: [uid_t(501), 502], [true, false])
    func `cutover controls use the protection owner and start requires the console`(_ uid: uid_t, _ console: Bool) async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in console }),
        )
        let transport = try await handshaken(dispatcher, uid: uid)
        for request in [
            Request.startCutover(profileID: service.profile, confirmWithin: 600, hasSecrets: false),
            .confirmCutover,
            .abortCutover,
        ] {
            let reply = try await call(transport, request)
            if uid != 501 {
                #expect(reply == .error(.notAuthorised(.notOwner)))
            } else if !console, request.kind != .abortCutover {
                #expect(reply == .error(.notAuthorised(.notConsoleUser)))
            } else {
                #expect(reply == .ok)
            }
        }
    }

    @Test
    func `abort remains available during recovery and secret method is enforced`() async throws {
        let service = DispatcherService()
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
        )
        let transport = try await handshaken(dispatcher)
        #expect(try await call(transport, .startCutover(profileID: service.profile, confirmWithin: 600, hasSecrets: true)) ==
            .error(.malformedMessage))
        await dispatcher.setRecovering(true)
        #expect(try await call(transport, .abortCutover) == .ok)
        #expect(Envelope.currentProtocolVersion == 8)
    }
}
