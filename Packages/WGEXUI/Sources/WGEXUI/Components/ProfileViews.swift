// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// What a profile row or card shows.
public nonisolated struct ProfileSummary: Sendable, Hashable, Identifiable {
    /// Profile identifier.
    public var id: UUID
    /// Display name.
    public var name: String
    /// First peer's endpoint.
    public var endpoint: Endpoint?
    /// Number of peers.
    public var peerCount: Int
    /// Verdict when this is the selected tunnel; nil otherwise.
    public var verdict: ProtectionVerdict?

    /// Creates a summary.
    public init(id: UUID, name: String, endpoint: Endpoint?, peerCount: Int, verdict: ProtectionVerdict?) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.peerCount = peerCount
        self.verdict = verdict
    }

    /// "vpn.example.com:51820", "… and 2 more peers", or "No endpoint".
    public var endpointSummary: String {
        guard let endpoint else {
            return peerCount > 1 ? MacStrings.peersNoEndpoint(String(peerCount)) : MacStrings.noEndpoint
        }
        let base = EndpointText.format(endpoint)
        switch peerCount {
        case ...1: return base
        case 2: return MacStrings.endpointWithOneMorePeer(String(base))
        default: return MacStrings.endpointWithMorePeers(String(base), String(peerCount - 1))
        }
    }

    /// State text; "Not connected" when not the selected tunnel.
    public var stateTitle: String {
        verdict?.chipTitle ?? MacStrings.notConnected
    }

    /// Dot colour.
    public var stateColour: StateColor {
        verdict?.colour ?? .unknown
    }

    /// "Home, Protected, vpn.example.com:51820".
    public var accessibilityLabel: String {
        MacStrings.profileAnnouncement(String(name), String(stateTitle), String(endpointSummary))
    }
}

/// A list row: state dot, name, endpoint summary and state text.
public struct ProfileRow: View {
    private let summary: ProfileSummary

    /// Creates a row.
    public init(summary: ProfileSummary) {
        self.summary = summary
    }

    /// The view body.
    public var body: some View {
        HStack(spacing: Spacing.medium) {
            StateDot(colour: summary.stateColour)
                .opacity(summary.verdict == nil ? 0 : 1)
            VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                Text(summary.name)
                    .font(Typography.body)
                Text(summary.endpointSummary)
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: Spacing.small)
            if summary.verdict != nil {
                Text(summary.stateTitle)
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(summary.accessibilityLabel)
    }
}

/// A card: name with state dot, endpoint summary and a state chip.
public struct ProfileCard: View {
    private let summary: ProfileSummary

    /// Creates a card.
    public init(summary: ProfileSummary) {
        self.summary = summary
    }

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.medium) {
            HStack(spacing: Spacing.small) {
                StateDot(colour: summary.stateColour)
                Text(summary.name)
                    .font(Typography.cardTitle)
            }
            Text(summary.endpointSummary)
                .font(Typography.caption)
                .foregroundStyle(.secondary)
            StateChip(title: summary.stateTitle, glyph: summary.verdict?.glyph ?? "circle", colour: summary.stateColour)
                .wgexAX(.profiles, "state", label: summary.stateTitle, item: summary.id.uuidString)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(summary.accessibilityLabel)
    }
}
