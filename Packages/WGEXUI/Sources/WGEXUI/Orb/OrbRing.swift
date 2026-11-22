// SPDX-License-Identifier: MIT

import SwiftUI

/// The orb ring: none, indeterminate (rotating arc, or three dots cycling at
/// 1 Hz with Reduce Motion), solid or dashed.
package struct OrbRing: View {
    package let style: RingStyle
    package let colour: StateColor
    package let size: ConnectionOrb.Size

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.wgexSurfaceAnimating) private var animating

    package var body: some View {
        ZStack {
            switch style {
            case .none:
                Color.clear
            case .indeterminate:
                if !animating {
                    Circle().trim(from: 0, to: 0.7).stroke(colour.color, lineWidth: size.ringWidth)
                } else if reduceMotion {
                    OrbDots(colour: colour, size: size)
                } else {
                    RotatingArc(colour: colour, lineWidth: size.ringWidth)
                }
            case .solid:
                Circle()
                    .strokeBorder(colour.color, lineWidth: size.ringWidth)
            case .dashed:
                Circle()
                    .strokeBorder(colour.color, style: dashStyle)
            }
        }
        .padding(size.ringWidth)
        .transition(.opacity)
        .id(style)
    }

    private var dashStyle: StrokeStyle {
        StrokeStyle(lineWidth: size.ringWidth, lineCap: .round, dash: [size.ringWidth * 2.5, size.ringWidth * 2])
    }
}

/// An arc turning once every ``OrbMotion/rotationPeriod`` seconds, derived
/// from the timeline date so it never jumps back.
private struct RotatingArc: View {
    let colour: StateColor
    let lineWidth: CGFloat

    var body: some View {
        TimelineView(.animation) { context in
            let turns = context.date.timeIntervalSinceReferenceDate / OrbMotion.rotationPeriod
            Circle()
                .trim(from: 0, to: 0.7)
                .stroke(colour.color, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .padding(lineWidth / 2)
                .rotationEffect(.degrees(turns.truncatingRemainder(dividingBy: 1) * 360))
        }
    }
}

/// Reduce Motion indeterminate indicator: three dots, one highlighted, the
/// highlight stepping once per second.
private struct OrbDots: View {
    let colour: StateColor
    let size: ConnectionOrb.Size

    var body: some View {
        TimelineView(.periodic(from: .now, by: OrbMotion.reducedDotStep)) { context in
            let active = Int(context.date.timeIntervalSinceReferenceDate / OrbMotion.reducedDotStep) % 3
            HStack(spacing: size.ringWidth * 1.5) {
                ForEach(0 ..< 3, id: \.self) { index in
                    Circle()
                        .fill(colour.color.opacity(index == active ? 1 : 0.3))
                        .frame(width: size.ringWidth * 2, height: size.ringWidth * 2)
                }
            }
            .animation(OrbMotion.reducedCrossFade.animation, value: active)
            .frame(maxHeight: .infinity, alignment: .bottom)
            .padding(.bottom, size.diameter * 0.12)
        }
    }
}
