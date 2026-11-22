// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI
    import Testing
    import WGEXCore
    import WGEXUI
    import WGEXUITesting

    /// Renders the Mac previews to PNG in light and dark for design review. Runs only when `WGEX_DESIGN_SHOTS` names an output
    /// directory outside the repository; the window is never shown and no app is launched.
    @MainActor
    private struct MacDesignShotsTests {
        private nonisolated static let directory = ProcessInfo.processInfo.environment["WGEX_DESIGN_SHOTS"]

        private struct Shot {
            let name: String
            let size: CGSize
            let view: () -> AnyView
        }

        private static let window = CGSize(width: 1100, height: 860)
        private static let sheet = CGSize(width: 640, height: 680)
        private static let fullSheet = CGSize(width: 640, height: 2600)

        private var shots: [Shot] {
            [
                Shot(name: "tunnel-active", size: Self.window) { AnyView(MacScreenPreview(.window, verdict: .protected)) },
                Shot(name: "tunnel-inactive", size: Self.window) { AnyView(MacScreenPreview(.window, verdict: .inactive)) },
                Shot(name: "add-tunnel", size: CGSize(width: 520, height: 300)) { AnyView(MacScreenPreview(.importSource)) },
                Shot(name: "protection", size: Self.window) { AnyView(MacScreenPreview(.windowSettings(.protection))) },
                Shot(name: "log", size: Self.window) { AnyView(MacScreenPreview(.windowSettings(.diagnostics))) },
                Shot(name: "general", size: Self.window) { AnyView(MacScreenPreview(.windowSettings(.general))) },
                Shot(name: "background-service", size: Self.window) { AnyView(MacScreenPreview(.windowSettings(.service))) },
                Shot(name: "about", size: Self.window) { AnyView(MacScreenPreview(.windowSettings(.about))) },
                Shot(name: "edit-sheet", size: Self.sheet) { AnyView(MacScreenPreview(.editSheet)) },
                Shot(name: "edit-sheet-errors", size: Self.sheet) { AnyView(MacScreenPreview(.editSheetErrors)) },
                Shot(name: "edit-sheet-text", size: Self.sheet) { AnyView(MacScreenPreview(.editSheetText)) },
                Shot(name: "edit-sheet-full", size: Self.fullSheet) { AnyView(MacScreenPreview(.editSheetFull)) },
                Shot(name: "edit-sheet-long", size: Self.fullSheet) { AnyView(MacScreenPreview(.editSheetLong)) },
                Shot(name: "setup-welcome", size: CGSize(width: 520, height: 240)) { AnyView(MacScreenPreview(.onboarding(.welcome))) },
                Shot(name: "empty", size: Self.window) { AnyView(MacScreenPreview(.empty)) },
            ]
        }

        @Test(.enabled(if: directory != nil), arguments: [false, true])
        func `render the Mac previews to PNG`(_ dark: Bool) async throws {
            let directory = try #require(Self.directory)
            let root = URL(filePath: directory, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            _ = NSApplication.shared
            for shot in shots {
                let data = try await render(shot, dark: dark)
                try data.write(to: root.appending(path: "\(shot.name)-\(dark ? "dark" : "light").png"))
            }
        }

        private func render(_ shot: Shot, dark: Bool) async throws -> Data {
            let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let content = shot.view()
                .frame(width: shot.size.width, height: shot.size.height)
                .environment(\.colorScheme, dark ? .dark : .light)
            let host = NSHostingView(rootView: content)
            host.appearance = appearance
            let window = NSWindow(
                contentRect: CGRect(origin: CGPoint(x: -10000, y: -10000), size: shot.size),
                styleMask: [.borderless], backing: .buffered, defer: false,
            )
            window.isReleasedWhenClosed = false
            window.appearance = appearance
            window.contentView = host
            host.frame = CGRect(origin: .zero, size: shot.size)
            host.layoutSubtreeIfNeeded()
            // Lets `.task` modifiers and the first layout passes run.
            for _ in 0 ..< 6 {
                try await Task.sleep(for: .milliseconds(80))
                host.layoutSubtreeIfNeeded()
                host.display()
            }
            let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
            host.cacheDisplay(in: host.bounds, to: bitmap)
            window.close()
            return try #require(bitmap.representation(using: .png, properties: [:]))
        }
    }
#endif
