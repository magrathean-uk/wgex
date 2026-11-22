// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import Testing
    import UIKit
    import WGEXUI
    import WGEXUITesting

    /// Renders the iOS previews to PNG in light and dark for design review: the iPhone screens on an iPhone simulator, the
    /// iPad split view on an iPad simulator. Runs only when `WGEX_DESIGN_SHOTS` names an output directory outside the
    /// repository (xcodebuild passes `TEST_RUNNER_WGEX_DESIGN_SHOTS` through); no app is launched.
    @MainActor
    private struct IOSDesignShotsTests {
        private nonisolated static let directory = ProcessInfo.processInfo.environment["WGEX_DESIGN_SHOTS"]

        /// iPhone 18 Pro and iPad Pro 13-inch (M5, landscape) in points, with their status bar and home indicator insets.
        private static let phone = (size: CGSize(width: 402, height: 874), insets: UIEdgeInsets(top: 62, left: 0, bottom: 34, right: 0))
        private static let pad = (size: CGSize(width: 1376, height: 1032), insets: UIEdgeInsets(top: 24, left: 0, bottom: 20, right: 0))

        private static let phoneScreens: [IOSScreenPreview.Screen] = [
            .home, .tunnelActive, .tunnelInactive, .addTunnel, .protection, .log, .about, .onboarding, .partsList, .partsForm, .editor,
            .editorFull,
            .editorErrors,
            .editorLong,
            .editorLargeText,
            .editorSheet,
            .secretRevealed,
            .secretRevealedLarge,
        ]

        /// The iPad split view, the full-screen editor's top, whose cards stop at the grid's form width, and the editor in
        /// its sheet.
        private static let padScreens: [IOSScreenPreview.Screen] = [.split, .editor, .editorSheet]

        /// The screens rendered at the full editor height.
        private static let tallScreens: Set<IOSScreenPreview.Screen> = [.editorFull, .editorLong, .editorLargeText]

        /// The whole editor form, tall enough to show every group down to Diagnostics.
        private static let editorFullHeight: CGFloat = 3400

        @Test(.enabled(if: directory != nil), arguments: [false, true])
        func `render the iOS previews to PNG`(_ dark: Bool) async throws {
            let directory = try #require(Self.directory)
            let root = URL(filePath: directory, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let isPad = UIDevice.current.userInterfaceIdiom == .pad
            let device = isPad ? Self.pad : Self.phone
            for screen in isPad ? Self.padScreens : Self.phoneScreens {
                let size = Self.tallScreens.contains(screen) ? CGSize(width: device.size.width, height: Self.editorFullHeight) : device.size
                let data = try await render(screen, size: size, insets: device.insets, dark: dark)
                let name = "\(isPad ? "ipad" : "iphone")-\(screen.rawValue)-\(dark ? "dark" : "light").png"
                try data.write(to: root.appending(path: name))
            }
        }

        private func render(_ screen: IOSScreenPreview.Screen, size: CGSize, insets: UIEdgeInsets, dark: Bool) async throws -> Data {
            let bounds = CGRect(origin: .zero, size: size)
            // A test bundle has no window scene; the window is built through UIView's initialiser and never shown on screen.
            let window = try #require((UIWindow.self as UIView.Type).init(frame: bounds) as? UIWindow)
            window.overrideUserInterfaceStyle = dark ? .dark : .light
            let host = UIHostingController(rootView: IOSScreenPreview(screen))
            host.additionalSafeAreaInsets = insets
            window.rootViewController = host
            window.isHidden = false
            // Lets `.task` and `.onChange(initial:)` run and the navigation bars settle.
            for _ in 0 ..< 8 {
                try await Task.sleep(for: .milliseconds(100))
                host.view.setNeedsLayout()
                host.view.layoutIfNeeded()
            }
            let format = UIGraphicsImageRendererFormat()
            format.scale = window.traitCollection.displayScale > 0 ? window.traitCollection.displayScale : 3
            format.opaque = true
            let image = UIGraphicsImageRenderer(bounds: bounds, format: format).image { context in
                if !window.drawHierarchy(in: bounds, afterScreenUpdates: true) {
                    window.layer.render(in: context.cgContext)
                }
            }
            window.isHidden = true
            window.rootViewController = nil
            return try #require(image.pngData())
        }
    }
#endif
