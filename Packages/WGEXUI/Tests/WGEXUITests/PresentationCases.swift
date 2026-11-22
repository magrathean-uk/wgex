// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

/// One status and context with the verdict the mapping must produce.
package nonisolated struct PresentationCase: Sendable, CustomTestStringConvertible {
    package let name: String
    package let status: TunnelStatus
    package let context: ProtectionContext
    package let expected: ProtectionVerdict

    package var testDescription: String {
        name
    }

    package var presentation: ProtectionPresentation {
        ProtectionPresentation(status: status, context: context)
    }
}

/// Every state in plan 06 §3 and ADR-009, every health level, every reassert
/// and unknown reason, platform-specific cases and the stale variant.
package nonisolated enum PresentationCases {
    package static let now = Date(timeIntervalSince1970: 1_800_000_000)
    package static let generation = Generation(rawValue: 7)

    package static func status(
        _ phase: TunnelPhase,
        _ protection: ProtectionState,
        health: TunnelHealth = .idle,
    ) -> TunnelStatus {
        TunnelStatus(phase: phase, protection: protection, transport: nil, health: health, recentEvents: [])
    }

    package static func context(
        _ platform: ProtectionContext.Platform = .mac,
        staleness: Staleness = .fresh,
        userInitiated: Bool = false,
        reason: UnknownReason? = nil,
    ) -> ProtectionContext {
        ProtectionContext(platform: platform, now: now, staleness: staleness, userInitiated: userInitiated, unknownReason: reason)
    }

    package static func health(_ level: TunnelHealth.Level, handshakeAge: TimeInterval? = nil, rate: Double = 0) -> TunnelHealth {
        TunnelHealth(level: level, lastHandshake: handshakeAge.map { now.addingTimeInterval(-$0) }, rxRate: rate, txRate: rate)
    }

    package static let all: [PresentationCase] = protectedCases + transitionalCases + blockedCases + otherCases + unknownCases

    private static let active = TunnelPhase.active(generation)

    private static let protectedCases: [PresentationCase] = [
        PresentationCase(
            name: "protected, transferring",
            status: status(active, .protected, health: health(.healthy, handshakeAge: 18, rate: 2400)),
            context: context(),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, healthy, quiet",
            status: status(active, .protected, health: health(.healthy, handshakeAge: 18)),
            context: context(.iOS),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, idle",
            status: status(active, .protected, health: health(.idle)),
            context: context(.tvOS),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, degraded",
            status: status(active, .protected, health: health(.degraded(reason: "txWithoutRx"), handshakeAge: 40)),
            context: context(),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, unresponsive",
            status: status(active, .protected, health: health(.unresponsive, handshakeAge: 180)),
            context: context(),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, unresponsive, never",
            status: status(active, .protected, health: health(.unresponsive)),
            context: context(.iOS),
            expected: .protected,
        ),
        PresentationCase(
            name: "protected, offline",
            status: status(active, .protected, health: health(.offline, handshakeAge: 90)),
            context: context(),
            expected: .protected,
        ),
    ]

    private static let transitionalCases: [PresentationCase] = [
        PresentationCase(
            name: "connecting, preparing, blocked",
            status: status(.preparing(generation), .blocked),
            context: context(),
            expected: .connecting,
        ),
        PresentationCase(
            name: "connecting, configuring, unprotected",
            status: status(.configuring(generation), .unprotected),
            context: context(.iOS),
            expected: .connecting,
        ),
        PresentationCase(
            name: "connecting, tvOS, unsupported",
            status: status(.preparing(generation), .unsupported),
            context: context(.tvOS),
            expected: .connecting,
        ),
    ] + ReassertReason.allCases.map { reason in
        PresentationCase(
            name: "reasserting, \(reason.rawValue)",
            status: status(.reasserting(generation, reason: reason), .blocked),
            context: context(),
            expected: .reasserting,
        )
    } + [
        PresentationCase(
            name: "reasserting, iOS, protected",
            status: status(.reasserting(generation, reason: .wake), .protected),
            context: context(.iOS),
            expected: .reasserting,
        ),
    ]

    private static let blockedCases: [PresentationCase] = [
        PresentationCase(name: "blocked, active", status: status(active, .blocked), context: context(), expected: .blocked),
        PresentationCase(
            name: "blocked, failed, needs secrets",
            status: status(.failed(.secretsUnavailable, blockedByPolicy: true, needsSecrets: true), .blocked),
            context: context(),
            expected: .blocked,
        ),
        PresentationCase(
            name: "blocked, failed",
            status: status(.failed(.timedOut, blockedByPolicy: true, needsSecrets: false), .blocked),
            context: context(.iOS),
            expected: .blocked,
        ),
        PresentationCase(
            name: "blocked, stopping",
            status: status(.stopping(generation, reason: .logout), .blocked),
            context: context(),
            expected: .blocked,
        ),
        PresentationCase(name: "blocked, idle, lockdown", status: status(.idle, .blocked), context: context(), expected: .blocked),
        PresentationCase(name: "blocked claimed on tvOS", status: status(active, .blocked), context: context(.tvOS), expected: .unknown),
    ]

    private static let otherCases: [PresentationCase] = [
        PresentationCase(
            name: "captive window",
            status: status(
                .captiveWindow(generation, expires: now.addingTimeInterval(272)),
                .captiveWindow(expires: now.addingTimeInterval(272)),
            ),
            context: context(userInitiated: true),
            expected: .captiveWindow,
        ),
        PresentationCase(
            name: "captive window, expired",
            status: status(
                .captiveWindow(generation, expires: now.addingTimeInterval(-3)),
                .captiveWindow(expires: now.addingTimeInterval(-3)),
            ),
            context: context(),
            expected: .captiveWindow,
        ),
        PresentationCase(
            name: "captive window claimed on iOS",
            status: status(active, .captiveWindow(expires: now.addingTimeInterval(60))),
            context: context(.iOS),
            expected: .unknown,
        ),
        PresentationCase(name: "unprotected, idle", status: .idle, context: context(), expected: .unprotected),
        PresentationCase(
            name: "unprotected, user stop",
            status: .idle,
            context: context(.iOS, userInitiated: true),
            expected: .unprotected,
        ),
        PresentationCase(
            name: "unprotected, failed",
            status: status(.failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false), .unprotected),
            context: context(.tvOS),
            expected: .unprotected,
        ),
        PresentationCase(
            name: "unsupported, connected",
            status: status(active, .unsupported, health: health(.unresponsive, handshakeAge: 200)),
            context: context(.tvOS),
            expected: .unsupported,
        ),
        PresentationCase(name: "unsupported, idle", status: status(.idle, .unsupported), context: context(.iOS), expected: .unsupported),
        PresentationCase(
            name: "stale",
            status: status(active, .protected),
            context: context(staleness: .stale(since: now.addingTimeInterval(-42))),
            expected: .stale,
        ),
        PresentationCase(
            name: "unknown, never reported",
            status: .idle,
            context: context(.iOS, staleness: .stale(since: .distantPast)),
            expected: .unknown,
        ),
    ]

    private static let unknownReasons: [(String, UnknownReason?)] = [
        ("verification failed", .verificationFailed),
        ("not reporting", .notReporting(since: now.addingTimeInterval(-12))),
        ("extension unavailable", .extensionUnavailable),
        ("secure install pending", .secureInstallPending),
        ("settings pending", .settingsPending),
        ("inconsistent", .inconsistentState),
        ("unspecified", .unspecified),
        ("no reason", nil),
    ]

    private static let unknownCases: [PresentationCase] = unknownReasons.map { name, reason in
        PresentationCase(name: "unknown, \(name)", status: status(active, .unknown), context: context(reason: reason), expected: .unknown)
    } + [
        PresentationCase(
            name: "unknown, iOS not reporting",
            status: status(.idle, .unknown),
            context: context(.iOS, reason: .notReporting(since: now.addingTimeInterval(-12))),
            expected: .unknown,
        ),
    ]
}
