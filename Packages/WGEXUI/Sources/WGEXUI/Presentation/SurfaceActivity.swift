// SPDX-License-Identifier: MIT

import Foundation
import SwiftUI

// SwiftFormat does not recognise public declarations expanded by @Entry.
// swiftformat:disable docComments
public extension EnvironmentValues {
    /// A containing status timeline or deterministic preview supplies its display date.
    @Entry var wgexDisplayDate: Date? = nil

    /// Whether the containing surface can currently display ages and countdowns.
    @Entry var wgexSurfaceVisible: Bool = true

    /// Whether the containing window is visible and key; previews default to active.
    @Entry var wgexSurfaceAnimating: Bool = true
}

// swiftformat:enable docComments

#if os(macOS)
    import AppKit

    public extension View {
        /// Tracks native occlusion, key status and app hiding without polling.
        func macSurfaceActivity(changed: @escaping (Bool) -> Void = { _ in }) -> some View {
            modifier(MacSurfaceActivity(changed: changed))
        }
    }

    private struct MacSurfaceActivity: ViewModifier {
        let changed: (Bool) -> Void
        @Environment(\.scenePhase) private var scenePhase
        @State private var visible = false
        @State private var key = false
        @State private var presented = true

        func body(content: Content) -> some View {
            content
                .environment(\.wgexSurfaceVisible, visible && presented)
                .environment(\.wgexSurfaceAnimating, visible && key && presented && scenePhase == .active)
                .background(WindowProbe { showing, isKey in
                    visible = showing; key = isKey
                    changed(showing && presented)
                })
                .onAppear { presented = true; changed(visible) }
                .onDisappear { presented = false; changed(false) }
        }
    }

    private struct WindowProbe: NSViewRepresentable {
        let changed: (Bool, Bool) -> Void
        func makeNSView(context _: Context) -> Probe {
            Probe(changed: changed)
        }

        func updateNSView(_ view: Probe, context _: Context) {
            view.changed = changed
        }

        @MainActor
        final class Probe: NSView {
            var changed: (Bool, Bool) -> Void
            init(changed: @escaping (Bool, Bool) -> Void) {
                self.changed = changed
                super.init(frame: .zero)
                let center = NotificationCenter.default
                for name in [
                    NSWindow.didChangeOcclusionStateNotification,
                    NSWindow.didBecomeKeyNotification,
                    NSWindow.didResignKeyNotification,
                    NSWindow.willCloseNotification,
                    NSApplication.didHideNotification,
                    NSApplication.didUnhideNotification,
                ] {
                    center.addObserver(self, selector: #selector(refresh), name: name, object: nil)
                }
            }

            required init?(coder: NSCoder) {
                nil
            }

            override func viewDidMoveToWindow() {
                super.viewDidMoveToWindow()
                refresh()
            }

            @objc private func refresh() {
                let visible = window?.occlusionState.contains(.visible) == true && !NSApplication.shared.isHidden
                let key = window?.isKeyWindow == true
                Task { @MainActor [weak self] in self?.changed(visible, key) }
            }

            deinit { NotificationCenter.default.removeObserver(self) }
        }
    }
#endif
