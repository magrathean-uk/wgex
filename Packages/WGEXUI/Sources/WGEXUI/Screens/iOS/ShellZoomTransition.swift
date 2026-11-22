// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
#if os(iOS)
    import SwiftUI

    /// Keep the transition's concrete types separate when Reduce Motion changes.
    internal struct ShellZoomTransition<ID: Hashable>: ViewModifier {
        internal let id: ID
        internal let namespace: Namespace.ID
        @Environment(\.accessibilityReduceMotion) private var reduceMotion

        internal func body(content: Content) -> some View {
            if reduceMotion {
                content.navigationTransition(.crossFade)
            } else {
                content.navigationTransition(.zoom(sourceID: id, in: namespace))
            }
        }
    }
#endif
