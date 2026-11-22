// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXUI

public extension PreviewFixtures {
    /// A named presentation for galleries.
    struct NamedPresentation: Identifiable, Sendable {
        /// Display name, also the identifier.
        public let id: String
        /// The presentation.
        public let presentation: ProtectionPresentation
    }

    /// One presentation per orb state and health line, at ``referenceDate``.
    static let presentations: [NamedPresentation] = {
        let generation = Generation(rawValue: 3)
        let active = TunnelPhase.active(generation)
        let now = referenceDate
        let mac = ProtectionContext(platform: .mac, now: now)
        func status(_ phase: TunnelPhase, _ protection: ProtectionState, _ health: TunnelHealth = .idle) -> TunnelStatus {
            TunnelStatus(phase: phase, protection: protection, transport: nil, health: health, recentEvents: [])
        }
        func health(_ level: TunnelHealth.Level, handshake: TimeInterval?, rate: Double = 0) -> TunnelHealth {
            TunnelHealth(level: level, lastHandshake: handshake.map { now.addingTimeInterval(-$0) }, rxRate: rate, txRate: rate)
        }
        let expires = referenceDate.addingTimeInterval(272)
        var reporting = mac
        reporting.unknownReason = .notReporting(since: referenceDate.addingTimeInterval(-12))
        var stale = mac
        stale.staleness = .stale(since: referenceDate.addingTimeInterval(-42))
        let entries: [(String, TunnelStatus, ProtectionContext)] = [
            ("Protected, transferring", status(active, .protected, health(.healthy, handshake: 18, rate: 1_250_000)), mac),
            ("Protected, idle", status(active, .protected, health(.idle, handshake: 70)), mac),
            ("Protected, peer not responding", status(active, .protected, health(.unresponsive, handshake: 180)), mac),
            ("Connecting", status(.preparing(generation), .blocked), mac),
            ("Reconnecting", status(.reasserting(generation, reason: .pathChanged), .blocked), mac),
            ("Traffic blocked", status(.failed(.timedOut, blockedByPolicy: true, needsSecrets: false), .blocked), mac),
            ("Captive window", status(.captiveWindow(generation, expires: expires), .captiveWindow(expires: expires)), mac),
            ("Unprotected", status(.idle, .unprotected), mac),
            ("No kill switch (tvOS)", status(active, .unsupported), ProtectionContext(platform: .tvOS, now: referenceDate)),
            ("Unknown", status(active, .unknown), reporting),
            ("Stale", status(active, .protected), stale),
        ]
        return entries.map { NamedPresentation(id: $0.0, presentation: ProtectionPresentation(status: $0.1, context: $0.2)) }
            + [NamedPresentation(id: "Inactive", presentation: .inactive(activeTunnel: "Home"))]
    }()

    /// Recent events, oldest first, as a backend publishes them.
    static let events: [TunnelEvent] = {
        let generation = Generation(rawValue: 3)
        let kinds: [TunnelEvent.Kind] = [
            .phaseChanged, .protectionChanged(.blocked), .handshakeCompleted, .protectionChanged(.protected), .pathChanged,
            .txWithoutRx, .endpointChanged, .handshakeCompleted, .failed(.timedOut), .protectionChanged(.blocked),
        ]
        return kinds.enumerated().map { index, kind in
            TunnelEvent(date: referenceDate.addingTimeInterval(Double(index * 37 - 400)), kind: kind, generation: generation)
        }
    }()

    /// A deterministic 30-second download series ending at ``referenceDate``.
    static let downloadSeries: SparklineSeries = {
        var series = SparklineSeries()
        for tenth in 0 ..< 300 {
            let time = referenceDate.addingTimeInterval(Double(tenth - 300) / 10)
            let wave = sin(Double(tenth) / 18) * 400_000 + 600_000
            series.append(tenth == 210 ? 2_400_000 : wave, at: time)
        }
        return series
    }()

    /// Profile summaries, one per verdict plus an unselected profile.
    static let profileSummaries: [ProfileSummary] = {
        guard let endpoint = try? Endpoint(validatingHost: "vpn.example.com", port: 51820),
              let cabinEndpoint = try? Endpoint(validatingHost: "2001:db8::7", port: 51820) else { return [] }
        let unselected = ProfileSummary(
            id: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0)),
            name: "Cabin",
            endpoint: cabinEndpoint,
            peerCount: 3,
            verdict: nil,
        )
        return [unselected] + ProtectionVerdict.allCases.enumerated().map { index, verdict in
            ProfileSummary(
                id: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, UInt8(index))),
                name: "Home",
                endpoint: endpoint,
                peerCount: 1,
                verdict: verdict,
            )
        }
    }()
}
