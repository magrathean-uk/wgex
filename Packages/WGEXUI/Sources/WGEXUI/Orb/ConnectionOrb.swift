// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// The signature connection orb (plan 06 §3): a circular interactive glass
/// surface with a state glyph and ring, and up to two plain tinted labels.
public struct ConnectionOrb: View {
    /// The four prescribed diameters.
    public enum Size: CGFloat, CaseIterable, Sendable {
        /// Mac menu bar extra.
        case menuBar = 96
        /// iPhone and iPad status tab.
        case compact = 160
        /// Mac main window status card.
        case window = 220
        /// Apple TV connection tab.
        case television = 320

        /// Diameter in points.
        public var diameter: CGFloat {
            rawValue
        }

        /// Point size of the core glyph.
        public var glyphSize: CGFloat {
            (rawValue * 0.34).rounded()
        }

        /// Ring stroke width.
        public var ringWidth: CGFloat {
            max(3, (rawValue * 0.035).rounded())
        }
    }

    private let presentation: ProtectionPresentation
    private let size: Size
    private let transportChip: OrbChip?
    private let transportPickerEnabled: Bool
    private let actionTitle: String?
    private let onToggle: (ProtectionAction) -> Void
    private let onTransportPicker: () -> Void

    @Namespace private var glassNamespace
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.wgexSurfaceAnimating) private var animating
    @State private var displayed: ProtectionPresentation
    @State private var tapCount = 0
    @State private var bloomCount = 0
    @State private var longPressFired = false

    /// Creates an orb. `transportName` is shown as a chip only when relay
    /// transports are on; the long press calls `onTransportPicker` only when
    /// `transportPickerEnabled` is true. `actionTitle` replaces the presentation's action title in the accessibility hint and
    /// input label, for a surface whose tap does something else (the Mac arms on-demand instead of connecting).
    public init(
        presentation: ProtectionPresentation,
        size: Size = .compact,
        transportName: String? = nil,
        transportPickerEnabled: Bool = false,
        actionTitle: String? = nil,
        onToggle: @escaping (ProtectionAction) -> Void,
        onTransportPicker: @escaping () -> Void = {},
    ) {
        self.presentation = presentation
        self.size = size
        transportChip = transportName.map {
            OrbChip(
                slot: .transport,
                glyph: $0 == MacStrings.directWireGuard ? "network" : "arrow.left.arrow.right",
                title: $0,
                colour: $0 == MacStrings.directWireGuard ? .unknown : .transport,
            )
        }
        self.transportPickerEnabled = transportPickerEnabled
        self.actionTitle = actionTitle
        self.onToggle = onToggle
        self.onTransportPicker = onTransportPicker
        _displayed = State(initialValue: presentation)
    }

    /// Creates an orb straight from a backend status.
    public init(
        status: TunnelStatus,
        context: ProtectionContext = ProtectionContext(),
        size: Size = .compact,
        transportName: String? = nil,
        transportPickerEnabled: Bool = false,
        onToggle: @escaping (ProtectionAction) -> Void,
        onTransportPicker: @escaping () -> Void = {},
    ) {
        self.init(
            presentation: ProtectionPresentation(status: status, context: context),
            size: size,
            transportName: transportName,
            transportPickerEnabled: transportPickerEnabled,
            onToggle: onToggle,
            onTransportPicker: onTransportPicker,
        )
    }

    /// The view body.
    public var body: some View {
        GlassEffectContainer(spacing: Spacing.medium) {
            VStack(spacing: Spacing.medium) {
                surfaceButton
                OrbChipRow(chips: chips)
            }
        }
        .onChange(of: presentation) { old, new in
            apply(new, from: old)
        }
        .modifier(OrbFeedback(presentation: displayed, tapCount: tapCount))
        .accessibilityElement(children: .ignore)
        .accessibilityHint(actionTitle ?? displayed.action.title)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { toggle() }
        .accessibilityActions {
            if transportPickerEnabled {
                Button(MacStrings.chooseTransport, action: onTransportPicker)
            }
        }
        .wgexControl(
            .connection,
            "orb",
            label: Self.accessibilityLabel(for: displayed, transport: transportChip),
            inputLabel: actionTitle ?? displayed.action.title,
        )
    }

    /// Chips under the orb: transport first, then health; at most two.
    public var chips: [OrbChip] {
        Array([transportChip, displayed.healthChip].compactMap(\.self).prefix(2))
    }

    /// VoiceOver label for a presentation and optional transport chip.
    public static func accessibilityLabel(for presentation: ProtectionPresentation, transport: OrbChip? = nil) -> String {
        let transportText = transport.map { " " + $0.accessibilityLabel + "." } ?? ""
        return MacStrings.connectionStatus + presentation.accessibilityLabel + transportText
    }

    private var surfaceButton: some View {
        Button(action: toggle) {
            surface
        }
        .buttonStyle(.plain)
        #if !os(tvOS)
            .simultaneousGesture(
                LongPressGesture(minimumDuration: 0.5).onEnded { _ in
                    longPressFired = true
                    onTransportPicker()
                },
                isEnabled: transportPickerEnabled,
            )
        #endif
    }

    private var surface: some View {
        ZStack {
            OrbRing(style: displayed.ring, colour: displayed.colour, size: size)
            VStack(spacing: Spacing.small) {
                OrbGlyph(presentation: displayed, size: size)
                OrbCountdown(presentation: displayed)
                    .font(.title2.weight(.semibold)).monospacedDigit()
            }
        }
        .frame(width: size.diameter, height: size.diameter)
        .contentShape(.circle)
        .glassEffect(.regular.interactive(), in: .circle)
        .glassEffectID(OrbGlassID.surface, in: glassNamespace)
        .modifier(OrbBloom(trigger: bloomCount, colour: displayed.colour, diameter: size.diameter))
        .modifier(OrbBreathing(active: displayed.verdict == .protected && !reduceMotion && animating))
    }

    private func toggle() {
        if longPressFired {
            longPressFired = false
            return
        }
        tapCount += 1
        onToggle(displayed.action)
    }

    private func apply(_ new: ProtectionPresentation, from old: ProtectionPresentation) {
        guard old.verdict != new.verdict else {
            displayed = new
            return
        }
        let transition = OrbMotion.transition(from: old.verdict, to: new.verdict, reduceMotion: reduceMotion || !animating)
        withAnimation(transition.animation) {
            displayed = new
        }
        if OrbMotion.blooms(from: old.verdict, to: new.verdict, reduceMotion: reduceMotion || !animating) {
            bloomCount += 1
        }
    }
}

/// Glass identities inside the orb's container.
private nonisolated enum OrbGlassID: Hashable, Sendable {
    case surface
}

private struct OrbGlyph: View {
    let presentation: ProtectionPresentation
    let size: ConnectionOrb.Size

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Image(systemName: presentation.glyph)
            .font(.system(size: size.glyphSize, weight: .semibold))
            .foregroundStyle(presentation.colour.color)
            .contentTransition(reduceMotion ? .opacity : .symbolEffect(.replace))
            .animation(
                reduceMotion ? OrbMotion.reducedCrossFade.animation : .smooth(duration: OrbMotion.glyphMorphDuration),
                value: presentation.glyph,
            )
    }
}

private struct OrbChipRow: View {
    let chips: [OrbChip]
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: Spacing.small) {
            ForEach(chips) { chip in
                Label {
                    Text(chip.title)
                } icon: {
                    Image(systemName: chip.glyph)
                        .foregroundStyle(chip.colour.color)
                }
                .font(Typography.caption.weight(.semibold))
                .padding(.horizontal, Spacing.medium)
                .padding(.vertical, Spacing.small)
                .foregroundStyle(chip.colour.labelColor(for: scheme))
                .accessibilityLabel(chip.accessibilityLabel)
                .accessibilityIdentifier("wgex.connection.chip.\(chip.slot.rawValue)")
            }
        }
    }
}

private struct OrbCountdown: View {
    let presentation: ProtectionPresentation
    @Environment(\.wgexSurfaceVisible) private var visible
    @Environment(\.wgexDisplayDate) private var displayDate

    var body: some View {
        if presentation.countdownExpiry != nil {
            if let displayDate {
                Text(presentation.countdownText(at: displayDate) ?? "")
            } else if visible {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(presentation.countdownText(at: context.date) ?? "")
                }
            } else {
                Text(presentation.countdownText(at: .now) ?? "")
            }
        }
    }
}
