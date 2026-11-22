// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5SecretsWireTests {
    @Test
    func `app callback refusal retains its typed cause over the wire`() async {
        let app = ClientEventsExport(callbacks: .init(provideSecrets: { _ in throw DaemonError.unauthorised }))
        let callback = NSXPCDaemonListener.secretsCallback(proxy: { _ in app })
        await #expect(throws: DaemonFailure(wire: .unauthorised)) { _ = try await callback(UUID()) }
    }

    @Test
    func `listener callback payload round trips through the app decoder`() throws {
        let id = UUID()
        let bytes = try NSXPCDaemonListener.encodeSecretsRequest(id)
        #expect(try ClientEventsExport.decodeSecretsRequest(bytes) == id)
    }

    @Test
    func `real callback builder reaches the real app export`() async throws {
        let id = UUID()
        let app = ClientEventsExport(callbacks: .init(provideSecrets: { requested in
            #expect(requested == id)
            return Data([1, 2, 3]) // Marker only, no secret material.
        }))
        let callback = NSXPCDaemonListener.secretsCallback(proxy: { _ in app })
        #expect(try await callback(id) == Data([1, 2, 3]))
    }
}
