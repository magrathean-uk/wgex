// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import OSLog
    import WGEXUI

    /// The S-tunnel glyphs (the app icon's shape) are 18 pt monochrome templates: the middle swelling is
    /// solid with a keyhole while protected, connecting or reasserting, and empty when inactive or
    /// unsupported. Attention states retain distinct monochrome symbols as well as tooltips.
    public enum MacStatusImage {
        private static var cached: (ProtectionVerdict, NSImage)?
        private static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "com.magrathean.WGEXApp", category: "statusimage")

        /// Returns the same template until the verdict changes; age updates allocate nothing.
        public static func make(for verdict: ProtectionVerdict) -> NSImage {
            if let cached, cached.0 == verdict {
                return cached.1
            }
            let found: NSImage? = switch verdict {
            case .protected, .connecting, .reasserting:
                NSImage(named: "WGEXMenuBar")
            case .inactive, .unsupported, .unprotected:
                NSImage(named: "WGEXMenuBarOff")
            case .blocked:
                Self.symbol("exclamationmark.shield")
            case .captiveWindow:
                Self.symbol("timer")
            case .unknown, .stale:
                Self.symbol("questionmark.diamond")
            }
            let template = ((found ?? Self.fallback(for: verdict)).copy() as? NSImage) ?? NSImage()
            template.size = NSSize(width: 18, height: 18)
            template.isTemplate = true
            // A missing image is logged and shown as a visible stand-in; it is never cached, so a later
            // call retries the lookup instead of pinning a stand-in to the verdict.
            if found != nil {
                cached = (verdict, template)
            }
            return template
        }

        private static func symbol(_ name: String) -> NSImage? {
            NSImage(systemSymbolName: name, accessibilityDescription: nil)
        }

        /// Never blank and never another state's glyph: a generic, visibly different symbol.
        private static func fallback(for verdict: ProtectionVerdict) -> NSImage {
            log.fault("Menu bar image missing for a verdict; using a stand-in: \(String(describing: verdict), privacy: .public)")
            assertionFailure("Menu bar image missing for \(verdict)")
            return symbol("questionmark.circle") ?? NSImage(size: NSSize(width: 18, height: 18))
        }
    }
#endif
