// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct DaemonErrorTests {
    @Test(arguments: [
        DaemonError.secretsUnavailable,
        .protectionUnknown(reason: "secretsHandoffDisconnected"),
        .malformedMessage, .messageTooLarge(1025), .unsupportedProtocolVersion(2),
        .notAuthorised(.notOwner), .profileNotFound(UUID()), .busy, .rateLimited,
        .unauthorised, .handshakeRequired, .staleGeneration, .anotherTunnelActive, .disconnected, .subscriptionLimit,
        .onDemandNotConfigured,
        .uninstallFailed(step: .admission), .uninstallFailed(step: .releaseReference), .uninstallFailed(step: .purgeState),
        .tunnel(.anotherTunnelActive),
        .tunnel(.invalidConfiguration(.invalidProfile)), .tunnel(.invalidConfiguration(.statisticsInterval)), .tunnel(.engine(code: -9)),
        .downgradeDetected,
        .secureInstallRequired,
        .protectionUnknown(reason: "Verification pending"),
    ])
    func `security errors round trip through the existing reply envelope`(error: DaemonError) throws {
        let reply = Reply.error(error)
        #expect(try WireCodec.decode(Reply.self, from: WireCodec.encode(reply)) == reply)
    }
}
