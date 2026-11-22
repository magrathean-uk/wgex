// SPDX-License-Identifier: MIT

import Foundation
#if os(macOS)
    import AppKit
#elseif os(iOS)
    import UIKit
    import UniformTypeIdentifiers
#endif

/// How a secret is written to a pasteboard.
public nonisolated struct SecretPasteboardOptions: Sendable, Hashable {
    /// Keep the item on this device (no Universal Clipboard).
    public var localOnly: Bool
    /// When the system should drop the item, if it supports expiry.
    public var expiresAt: Date?

    /// Creates options.
    public init(localOnly: Bool, expiresAt: Date?) {
        self.localOnly = localOnly
        self.expiresAt = expiresAt
    }
}

/// The pasteboard calls the copy policy needs; tests inject a fake.
public protocol SecretPasteboard: AnyObject {
    /// Changes whenever anything writes to the pasteboard.
    var changeCount: Int { get }
    /// Writes `text`; returns the change count after the write.
    @discardableResult
    func write(_ text: String, options: SecretPasteboardOptions) -> Int
    /// Removes every item.
    func clearContents()
}

/// Copy policy for secrets (plan 06 §4.2): local-only with a 60 s system
/// expiry on iOS; current-host-only and cleared after 60 s on macOS; no
/// pasteboard on tvOS.
public nonisolated struct SecretCopyPolicy: Sendable, Hashable {
    /// How the 60 s limit is enforced.
    public enum Mechanism: String, Sendable, Hashable {
        /// The system drops the item (`UIPasteboard` expiration date).
        case systemExpiry
        /// WGEX clears the pasteboard if nothing else was copied since.
        case scheduledClear
        /// No pasteboard on this platform.
        case unavailable
    }

    /// iOS and iPadOS.
    public static let iOS = SecretCopyPolicy(mechanism: .systemExpiry)
    /// macOS.
    public static let mac = SecretCopyPolicy(mechanism: .scheduledClear)
    /// tvOS.
    public static let tvOS = SecretCopyPolicy(mechanism: .unavailable)

    /// Mechanism.
    public var mechanism: Mechanism
    /// Lifetime of a copied secret.
    public var lifetime: Duration

    /// Creates a policy.
    public init(mechanism: Mechanism, lifetime: Duration = .seconds(60)) {
        self.mechanism = mechanism
        self.lifetime = lifetime
    }

    /// The policy for this platform.
    public static var current: SecretCopyPolicy {
        #if os(macOS)
            .mac
        #elseif os(tvOS)
            .tvOS
        #else
            .iOS
        #endif
    }

    /// Lifetime in seconds.
    public var lifetimeSeconds: TimeInterval {
        let parts = lifetime.components
        return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1e18
    }

    /// Write options at `now`, nil when copying is unavailable.
    public func options(now: Date) -> SecretPasteboardOptions? {
        switch mechanism {
        case .systemExpiry: SecretPasteboardOptions(localOnly: true, expiresAt: now.addingTimeInterval(lifetimeSeconds))
        case .scheduledClear: SecretPasteboardOptions(localOnly: true, expiresAt: nil)
        case .unavailable: nil
        }
    }
}

/// Result of a copy request.
public nonisolated enum SecretCopyOutcome: Sendable, Hashable {
    /// Copied; gone by `expiresAt`.
    case copied(expiresAt: Date)
    /// This platform has no pasteboard.
    case unavailable
    /// The secret could not be loaded.
    case nothingToCopy

    /// Status line under the field.
    public var message: String {
        switch self {
        case .copied: "Copied to this device only. It is cleared after 60 seconds"
        case .unavailable: "Copying is not available on this device"
        case .nothingToCopy: "The key is not available. Unlock this device and try again"
        }
    }
}

/// Copies secrets under a ``SecretCopyPolicy`` and, where the policy says so,
/// clears the pasteboard after the lifetime unless something else was
/// copied in the meantime.
@Observable
public final class SecretCopyController {
    /// Policy in force.
    public let policy: SecretCopyPolicy
    /// Result of the last copy.
    public private(set) var lastOutcome: SecretCopyOutcome?
    /// The pending clear, for tests and teardown.
    public private(set) var scheduledClear: Task<Void, Never>?

    @ObservationIgnored private let pasteboard: any SecretPasteboard?
    @ObservationIgnored private let clock: any Clock<Duration>
    @ObservationIgnored private let now: () -> Date

    /// Creates a controller. The defaults use the system pasteboard (none on
    /// tvOS), a continuous clock and the wall clock.
    public init(
        policy: SecretCopyPolicy = .current,
        pasteboard: any SecretPasteboard? = SystemSecretPasteboard.make(),
        clock: any Clock<Duration> = ContinuousClock(),
        now: @escaping () -> Date = { Date() },
    ) {
        self.policy = policy
        self.pasteboard = pasteboard
        self.clock = clock
        self.now = now
    }

    /// Whether copying is possible here.
    public var isAvailable: Bool {
        pasteboard != nil && policy.mechanism != .unavailable
    }

    /// Copies `secret` (nil when it could not be loaded).
    @discardableResult
    public func copy(_ secret: String?) -> SecretCopyOutcome {
        let outcome = perform(secret)
        lastOutcome = outcome
        return outcome
    }

    /// Cancels any pending clear without clearing.
    public func cancelScheduledClear() {
        scheduledClear?.cancel()
        scheduledClear = nil
    }

    private func perform(_ secret: String?) -> SecretCopyOutcome {
        guard let pasteboard, let options = policy.options(now: now()) else { return .unavailable }
        guard let secret, !secret.isEmpty else { return .nothingToCopy }
        cancelScheduledClear()
        let token = pasteboard.write(secret, options: options)
        let expiresAt = options.expiresAt ?? now().addingTimeInterval(policy.lifetimeSeconds)
        if policy.mechanism == .scheduledClear {
            let clock = clock
            let lifetime = policy.lifetime
            scheduledClear = Task { [weak pasteboard] in
                do {
                    try await clock.sleep(for: lifetime)
                } catch {
                    return
                }
                if let pasteboard, pasteboard.changeCount == token {
                    pasteboard.clearContents()
                }
            }
        }
        return .copied(expiresAt: expiresAt)
    }
}

/// The platform pasteboard behind ``SecretPasteboard``.
public enum SystemSecretPasteboard {
    /// The system pasteboard, or nil on tvOS.
    public static func make() -> (any SecretPasteboard)? {
        #if os(macOS)
            MacSecretPasteboard()
        #elseif os(iOS)
            PhoneSecretPasteboard()
        #else
            nil
        #endif
    }
}

#if os(macOS)
    /// `NSPasteboard.general`, current host only, marked concealed so
    /// clipboard managers skip it.
    private final class MacSecretPasteboard: SecretPasteboard {
        private let pasteboard = NSPasteboard.general

        var changeCount: Int {
            pasteboard.changeCount
        }

        func write(_ text: String, options: SecretPasteboardOptions) -> Int {
            pasteboard.prepareForNewContents(with: options.localOnly ? .currentHostOnly : [])
            pasteboard.setString(text, forType: .string)
            pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            return pasteboard.changeCount
        }

        func clearContents() {
            pasteboard.clearContents()
        }
    }

#elseif os(iOS)
    /// `UIPasteboard.general` with `localOnly` and `expirationDate`.
    private final class PhoneSecretPasteboard: SecretPasteboard {
        private let pasteboard = UIPasteboard.general

        var changeCount: Int {
            pasteboard.changeCount
        }

        func write(_ text: String, options: SecretPasteboardOptions) -> Int {
            var itemOptions: [UIPasteboard.OptionsKey: Any] = [.localOnly: options.localOnly]
            if let expiresAt = options.expiresAt {
                itemOptions[.expirationDate] = expiresAt
            }
            pasteboard.setItems([[UTType.utf8PlainText.identifier: text]], options: itemOptions)
            return pasteboard.changeCount
        }

        func clearContents() {
            pasteboard.items = []
        }
    }
#endif
