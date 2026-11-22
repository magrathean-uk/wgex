// SPDX-License-Identifier: MIT

#if os(tvOS)
    import SwiftUI
    import WGEXCore

    public struct TVConnectionScreen: View {
        public var name: String
        public var status: TunnelStatus
        public var settings: TVSettings
        public var flags: FeatureFlags
        public var sampledAt: Date?
        public var hasMeasurements: Bool
        public var busy: Bool
        public var action: (ProtectionAction) -> Void
        @Namespace private var focus
        @FocusState private var connectFocused: Bool

        public init(
            name: String,
            status: TunnelStatus,
            settings: TVSettings,
            flags: FeatureFlags = .defaults,
            sampledAt: Date? = nil,
            hasMeasurements: Bool = false,
            busy: Bool = false,
            action: @escaping (ProtectionAction) -> Void,
        ) {
            self.name = name; self.status = status; self.settings = settings; self.flags = flags
            self.sampledAt = sampledAt; self.hasMeasurements = hasMeasurements; self.busy = busy; self.action = action
        }

        public var body: some View {
            TimelineView(.periodic(from: .now, by: 1)) { timeline in
                let stale = Staleness.evaluate(lastUpdate: sampledAt, now: timeline.date)
                let presentation = TVConnectionState.presentation(status, now: timeline.date, staleness: stale)
                ScrollView {
                    VStack(alignment: .leading, spacing: 32) {
                        HStack(spacing: 80) {
                            ConnectionOrb(
                                presentation: presentation,
                                size: .television,
                                transportName: flags.relayTransports ? "Direct WireGuard" : nil,
                                onToggle: action,
                            )
                            .disabled(busy)
                            VStack(alignment: .leading, spacing: 24) {
                                Text(name).font(.title2)
                                Text(presentation.primary).font(.largeTitle.bold()).accessibilityIdentifier("tv.verdict")
                                Text(presentation.secondary).foregroundStyle(.secondary)
                                Button(presentation.action.title) { action(presentation.action) }
                                    .buttonStyle(.glassProminent).disabled(busy)
                                    .focused($connectFocused)
                                    .prefersDefaultFocus(true, in: focus)
                                    .accessibilityIdentifier("tv.connect")
                                StateChip(presentation: presentation)
                            }
                        }.focusSection()
                        HStack(spacing: 32) {
                            StatTile(title: "Last handshake", value: status.health.lastHandshake.map {
                                .age(since: $0, now: timeline.date)
                            } ?? .unavailable, isStale: presentation.isStale)
                            StatTile(
                                title: "Download",
                                value: !hasMeasurements ? .unavailable : .rate(status.health.rxRate),
                                isStale: presentation.isStale,
                            )
                            StatTile(
                                title: "Upload",
                                value: !hasMeasurements ? .unavailable : .rate(status.health.txRate),
                                isStale: presentation.isStale,
                            )
                        }
                        Text("Apple TV cannot enforce a kill switch").font(.footnote)
                        LabeledContent("Allow LAN", value: settings.allowLAN ? "On" : "Off")
                        if settings.eventsOnScreen {
                            EventsTimeline(events: TVConnectionState.events(status.recentEvents)).focusSection()
                        }
                    }.padding(60)
                }
            }
            .focusScope(focus)
            .defaultFocus($connectFocused, true)
            .navigationTitle("Connection")
        }
    }
#endif
