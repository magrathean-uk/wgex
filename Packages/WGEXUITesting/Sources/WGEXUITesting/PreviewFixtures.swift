// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXTesting

/// Deterministic data for SwiftUI previews and screenshot tests.
public enum PreviewFixtures {
    /// A named status for previews.
    public struct NamedStatus: Sendable, Identifiable {
        /// Display name, also the identifier.
        public let id: String
        /// The status.
        public let status: TunnelStatus
    }

    /// Fixed reference time so previews and screenshots are stable.
    public static let referenceDate = Date(timeIntervalSince1970: 1_800_000_000)

    /// One status per lifecycle phase.
    public static let statuses: [NamedStatus] = {
        let generation = Generation(rawValue: 3)
        let phases: [(String, TunnelPhase, ProtectionState)] = [
            ("Idle", .idle, .unprotected),
            ("Preparing", .preparing(generation), .blocked),
            ("Configuring", .configuring(generation), .blocked),
            ("Active", .active(generation), .protected),
            ("Reasserting", .reasserting(generation, reason: .wake), .blocked),
            (
                "Captive window",
                .captiveWindow(generation, expires: referenceDate.addingTimeInterval(300)),
                .captiveWindow(expires: referenceDate.addingTimeInterval(300)),
            ),
            ("Stopping", .stopping(generation, reason: .userRequested), .blocked),
            ("Failed", .failed(.timedOut, blockedByPolicy: true, needsSecrets: false), .blocked),
        ]
        return phases.map { name, phase, protection in
            NamedStatus(
                id: name,
                status: TunnelStatus(phase: phase, protection: protection, transport: nil, health: .idle, recentEvents: []),
            )
        }
    }()

    /// A profile for previews.
    public static let profile = TunnelProfile(
        id: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
        name: "Preview tunnel",
        createdAt: referenceDate,
    )

    /// A fake backend already showing `status`, with ``profile`` installed.
    public static func backend(showing status: TunnelStatus = .idle) async -> FakeTunnelBackend {
        let backend = FakeTunnelBackend()
        try? await backend.install(profile)
        backend.publish(status)
        return backend
    }

    /// A fake service controller in `state`; never touches the system.
    public static func serviceController(in state: ServiceState = .requiresApproval) -> FakeServiceController {
        FakeServiceController(initial: state)
    }
}
