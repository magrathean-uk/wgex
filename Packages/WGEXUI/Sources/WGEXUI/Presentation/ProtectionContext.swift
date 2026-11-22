// SPDX-License-Identifier: MIT

import Foundation

/// Inputs to the status mapping that are not part of ``WGEXCore/TunnelStatus``.
public nonisolated struct ProtectionContext: Sendable, Hashable {
    /// The platform the presentation is for.
    public enum Platform: String, CaseIterable, Sendable, Hashable {
        /// macOS (daemon backend).
        case mac
        /// iOS and iPadOS (Network Extension backend).
        case iOS
        /// tvOS (Network Extension backend; no kill switch).
        case tvOS

        /// The platform this build runs on.
        public static var current: Platform {
            #if os(macOS)
                .mac
            #elseif os(tvOS)
                .tvOS
            #else
                .iOS
            #endif
        }

        /// Name of the component that reports status.
        public var reporterName: String {
            self == .mac ? MacStrings.backgroundService : MacStrings.vpnExtension
        }
    }

    /// Platform.
    public var platform: Platform
    /// Wall-clock time for countdowns and ages.
    public var now: Date
    /// Whether the status is current.
    public var staleness: Staleness
    /// Whether the most recent transition was requested by the user.
    public var userInitiated: Bool
    /// Why protection is unknown, when the backend says so.
    public var unknownReason: UnknownReason?

    /// Creates a context.
    public init(
        platform: Platform = .current,
        now: Date = Date(),
        staleness: Staleness = .fresh,
        userInitiated: Bool = false,
        unknownReason: UnknownReason? = nil,
    ) {
        self.platform = platform
        self.now = now
        self.staleness = staleness
        self.userInitiated = userInitiated
        self.unknownReason = unknownReason
    }
}

/// Whether a status snapshot is recent enough to claim anything.
public nonisolated enum Staleness: Sendable, Hashable {
    /// Recent.
    case fresh
    /// Last update at `since`; the UI shows the stale variant.
    case stale(since: Date)

    /// Time of the last update when stale.
    public var since: Date? {
        if case let .stale(since) = self {
            return since
        }
        return nil
    }

    /// Age after which a status is stale.
    public static let threshold: TimeInterval = 15

    /// Stale when `lastUpdate` is missing or older than `threshold`.
    public static func evaluate(lastUpdate: Date?, now: Date, threshold: TimeInterval = threshold) -> Staleness {
        guard let lastUpdate else { return .stale(since: .distantPast) }
        return now.timeIntervalSince(lastUpdate) > threshold ? .stale(since: lastUpdate) : .fresh
    }
}
