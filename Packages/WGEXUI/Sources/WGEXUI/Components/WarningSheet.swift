// SPDX-License-Identifier: MIT

import SwiftUI

/// Copy for a consent sheet whose confirmation unlocks only after the reader
/// reaches the end.
public nonisolated struct WarningContent: Sendable, Hashable {
    /// Title.
    public var title: String
    /// Paragraphs, each a consequence.
    public var paragraphs: [String]
    /// Confirmation button title.
    public var confirmTitle: String
    /// Cancel button title.
    public var cancelTitle: String
    /// Hint shown until the end is reached.
    public var gateHint: String

    /// Creates content.
    public init(
        title: String,
        paragraphs: [String],
        confirmTitle: String,
        cancelTitle: String,
        gateHint: String = MacStrings.readToTheEndToContinue,
    ) {
        self.title = title
        self.paragraphs = paragraphs
        self.confirmTitle = confirmTitle
        self.cancelTitle = cancelTitle
        self.gateHint = gateHint
    }

    /// iOS "Force all traffic" consent (plan 06 §4.2, ADR-009): update
    /// lockout, update-time leak, CarPlay and Personal Hotspot, local DNS and mDNS.
    public static let forceAllTraffic = WarningContent(
        title: PlatformStrings.forceAllTraffic,
        paragraphs: [
            PlatformStrings.forceAllTrafficSendsEverything,
            PlatformStrings.appStoreAndTestFlightUpdates,
            PlatformStrings.whileAnUpdateInstallsTraffic,
            PlatformStrings.withLocalNetworkAccessAllowed,
            PlatformStrings.withLocalNetworkAccessBlocked,
            PlatformStrings.ifYouLoseInternetAfterAnUpdate,
            PlatformStrings.thisIsARoutingPolicyNotAPromise,
        ],
        confirmTitle: MacStrings.turnOn,
        cancelTitle: MacStrings.keepOff,
    )
}

/// Whether the reader has reached the end of a ``WarningSheet``.
public nonisolated struct WarningGate: Sendable, Hashable {
    /// Whether the end was reached.
    public private(set) var reachedEnd = false

    /// Creates a closed gate.
    public init() {}

    /// Confirmation is enabled only after the end is reached.
    public var canConfirm: Bool {
        reachedEnd
    }

    /// Records that the end of the content became visible.
    public mutating func markEndReached() {
        reachedEnd = true
    }
}

/// A consent sheet: consequences in a scroll view, confirmation disabled until
/// the reader scrolls to the bottom.
public struct WarningSheet: View {
    private let content: WarningContent
    private let onConfirm: () -> Void
    private let onCancel: () -> Void
    @State private var gate = WarningGate()

    /// Creates a sheet.
    public init(content: WarningContent, onConfirm: @escaping () -> Void, onCancel: @escaping () -> Void) {
        self.content = content
        self.onConfirm = onConfirm
        self.onCancel = onCancel
    }

    /// The view body.
    public var body: some View {
        VStack(spacing: Spacing.large) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.large) {
                    Text(content.title)
                        .font(.title2.weight(.bold))
                        .accessibilityLabel(Self.accessibilityLabel(for: content))
                        .accessibilityAddTraits(.isHeader)
                    ForEach(content.paragraphs, id: \.self) { paragraph in
                        Text(paragraph)
                            .font(Typography.body)
                            .fixedSize(horizontal: false, vertical: true)
                        #if os(tvOS)
                            .focusable()
                        #endif
                    }
                    Color.clear
                        .frame(height: 1)
                        .onAppear { gate.markEndReached() }
                        .accessibilityHidden(true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.glassPadding)
            }
            footer
        }
    }

    private var footer: some View {
        VStack(spacing: Spacing.small) {
            if !gate.canConfirm {
                Text(content.gateHint)
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: Spacing.medium) {
                Button(content.cancelTitle, action: onCancel)
                    .buttonStyle(.glass)
                Button(content.confirmTitle, action: onConfirm)
                    .buttonStyle(.glassProminent)
                    .disabled(!gate.canConfirm)
                    .accessibilityHint(gate.canConfirm ? "" : content.gateHint)
            }
        }
        .padding([.horizontal, .bottom], Spacing.glassPadding)
    }

    /// "Warning: Force all traffic".
    public static func accessibilityLabel(for content: WarningContent) -> String {
        MacStrings.warning(String(content.title))
    }
}
