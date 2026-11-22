// SPDX-License-Identifier: MIT

#if DEBUG || WGEX_LAB_BUILD
    import AppKit
    import SwiftUI
    import Testing
    import WGEXCore
    import WGEXTesting
    import WGEXUI

    /// The runner launches only in the lab; these views always use fake dependencies.
    @Suite(.enabled(if: HostedTestGate.enabled))
    @MainActor
    private struct HostedAccessibilityTests {
        @Test func `hosted status and onboarding expose labelled controls`() async {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true))
            // The empty window shows import and paste; a window with a tunnel shows its page (action, edit, export).
            let seeded = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [TunnelProfile(name: "Fixture")],
            )
            let hosts: [(WGEXAccessibility.Screen, [AnyView])] = [
                (.main, [AnyView(MacMainWindowView(model: model)), AnyView(MacMainWindowView(model: seeded))]),
                (.onboarding, [AnyView(MacOnboardingView(model: model))]),
                (.settings, [AnyView(MacSettingsView(model: model))]),
                (.importReview, [AnyView(MacImportSheet())]),
            ]
            #expect(hosts.map(\.0) == WGEXAccessibility.hostedScreens.filter { $0 != .menu })
            for (screen, views) in hosts {
                var identifiers = Set<String>()
                for view in views {
                    let window = hostWindow(view)
                    await Task.yield()
                    window.contentView?.layoutSubtreeIfNeeded()
                    identifiers.formUnion(collect(window))
                    window.close()
                }
                for entry in WGEXAccessibility.catalogue where entry.screen == screen && entry.requiredAtLaunch {
                    #expect(identifiers.contains { $0 == entry.id || $0.hasPrefix(entry.id + ".") }, "Missing \(entry.id)")
                }
            }
        }

        @Test func `every settings pane supports an accessibility tree read`() async {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true))
            for tab in MacSettingsTab.allCases {
                model.settingsTab = tab
                let window = hostWindow(MacSettingsView(model: model))
                await Task.yield()
                window.contentView?.layoutSubtreeIfNeeded()
                readLabels(window)
                window.close()
            }
        }

        private func readLabels(_ object: Any) {
            guard let element = object as? any NSAccessibilityProtocol else { return }
            _ = element.accessibilityLabel()
            for child in element.accessibilityChildren() ?? [] {
                readLabels(child)
            }
        }

        @Test func `hosted menu uses native disabled text and commands`() {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true))
            let controller = MacTextMenuController(model: model, perform: { _ in })
            #expect(controller.menu.items.allSatisfy { $0.view == nil })
            #expect(controller.menu.items.first?.title == "Status: Unknown")
            #expect(controller.menu.items.first?.isEnabled == false)
            #expect(controller.menu.items.last?.keyEquivalent == "q")
        }

        private func collect(_ object: Any) -> Set<String> {
            guard let element = object as? any NSAccessibilityProtocol else { return [] }
            var identifiers = Set<String>()
            if let identifier = element.accessibilityIdentifier(), identifier.hasPrefix("wgex.") {
                identifiers.insert(identifier)
                #expect(element.accessibilityLabel()?.isEmpty == false || element.accessibilityTitle()?.isEmpty == false)
            }
            for child in element.accessibilityChildren() ?? [] {
                identifiers.formUnion(collect(child))
            }
            return identifiers
        }

        private func hostWindow(_ view: some View) -> NSWindow {
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 1100, height: 900),
                styleMask: [.titled],
                backing: .buffered,
                defer: false,
            )
            window.isReleasedWhenClosed = false
            window.contentViewController = NSHostingController(rootView: view)
            window.makeKeyAndOrderFront(nil)
            return window
        }
    }
#endif
