// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

private struct WireMessagesTests {
    private static let profileID = UUID()

    private static let requests: [Request] = [
        .hello(clientVersion: "0.1", clientBuild: 1),
        .installProfile(DaemonProfile(profile: TunnelProfile(name: "Lab"), revision: 3)),
        .installProfileCAS(TunnelProfile(name: "CAS"), expectedRevision: nil),
        .profileRevision(profileID),
        .protectionReasons,
        .removeProfile(profileID, purgeSecrets: true),
        .startIntent(profileID: profileID, transport: nil, hasSecrets: true),
        .startIntent(profileID: profileID, transport: TransportID(), hasSecrets: false),
        .startCutover(profileID: profileID, confirmWithin: 600, hasSecrets: true), .confirmCutover, .abortCutover,
        .stop(profileID: profileID, reason: .userRequested),
        .selectTransport(profileID: profileID, transport: TransportID()),
        .setGlobalSettings(.defaults),
        .openCaptiveWindow(seconds: 300),
        .closeCaptiveWindow,
        .extendCaptiveWindow(seconds: 60),
        .subscribeEvents(includeLogs: true),
        .stopCurrent(reason: .userRequested),
        .setStartBeforeLoginIntent(profileID: profileID, enabled: true),
        .secureInstallStatus, .performSecureInstall, .status, .statusTelemetry,
        .statistics,
        .logs(since: Date(timeIntervalSince1970: 10), limit: 50),
        .diagnostics(DiagnosticsRequest(includeLogs: true, since: nil, profileIDs: [profileID])),
        .prepareForUpdate,
        .uninstall(purgeState: false),
        .armOnDemand(profileID: profileID, hasSecrets: true),
        .disarmOnDemand(profileID: profileID),
        .reportWiFiNetwork(WiFiObservation(interfaceName: "en0", reading: .ssid("Home"), observedAtContinuous: 12)),
    ]

    @Test(arguments: requests)
    func `every request round-trips in an envelope`(request: Request) throws {
        let envelope = Envelope(authorization: Data([1, 2, 3]), expectedGeneration: Generation(rawValue: 9), body: request)
        let data = try envelope.encoded()
        #expect(data.starts(with: Data("bplist".utf8)))
        #expect(try Envelope.decode(data) == envelope)
    }

    @Test
    func `protocol seven refuses the previous protocol six envelope`() throws {
        #expect(Envelope.currentProtocolVersion == 8)
        var previous = Envelope(body: .status)
        previous.protocolVersion = 6
        #expect(throws: DaemonError.unsupportedProtocolVersion(6)) { _ = try Envelope.decode(previous.encoded()) }
    }

    @Test
    func `request kinds cover every row`() {
        #expect(Set(Self.requests.map(\.kind)) == Set(RequestKind.allCases))
    }

    @Test
    func `replies and events round-trip`() throws {
        let replies: [Reply] = [
            .hello(HelloReply(daemonVersion: "0.1", daemonBuild: 1, protocolVersion: 1, minimumClientBuild: 1)),
            .ok,
            .started(Generation(rawValue: 7)),
            .status(.idle),
            .statistics(TunnelStatistics(
                generation: 7,
                sampledAt: Date(timeIntervalSince1970: 1),
                interfaceName: "utun9",
                listenPort: nil,
                peers: [],
            )),
            .logs([RedactedLogLine(date: Date(timeIntervalSince1970: 2), category: "daemon", message: "started", profileID: nil)]),
            .diagnostics(DiagnosticsBundle(createdAt: Date(timeIntervalSince1970: 3), archive: Data([0x50, 0x4B]))),
            .error(.notAuthorised(.notOwner)),
            .error(.tunnel(.anotherTunnelActive)),
        ]
        for reply in replies {
            #expect(try WireCodec.decode(Reply.self, from: WireCodec.encode(reply)) == reply)
        }
        let events: [Event] = [
            .status(.idle), .needsSecrets(profileID: Self.profileID),
            .statistics(TunnelStatistics(
                generation: 1,
                sampledAt: Date(timeIntervalSince1970: 0),
                interfaceName: nil,
                listenPort: nil,
                peers: [],
            )),
            .log(RedactedLogLine(date: Date(timeIntervalSince1970: 0), category: "test", message: "redacted", profileID: nil)),
            .wifiNetworkRequested(interfaceName: "en0"),
        ]
        for event in events {
            #expect(try WireCodec.decode(Event.self, from: WireCodec.encode(event)) == event)
        }
    }

    @Test
    func `XML and JSON are refused`() throws {
        let envelope = Envelope(body: .status)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .xml
        let xml = try encoder.encode(envelope)
        #expect(throws: DaemonError.malformedMessage) { _ = try Envelope.decode(xml) }
        let json = try JSONEncoder().encode(envelope)
        #expect(throws: DaemonError.malformedMessage) { _ = try Envelope.decode(json) }
    }

    @Test
    func `oversized and future messages are refused`() throws {
        let oversized = Data("bplist".utf8) + Data(count: WireCodec.maximumMessageSize)
        #expect(throws: DaemonError.messageTooLarge(oversized.count)) { _ = try Envelope.decode(oversized) }
        var future = Envelope(body: .status)
        future.protocolVersion = Envelope.currentProtocolVersion + 1
        let data = try WireCodec.encode(future)
        #expect(throws: DaemonError.unsupportedProtocolVersion(Envelope.currentProtocolVersion + 1)) { _ = try Envelope.decode(data) }
    }
}
