// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import WGEXCore

    public enum MacStartupOption: String, Codable, CaseIterable, Identifiable, Sendable {
        case off, login, boot
        public var id: Self {
            self
        }

        public var title: String {
            switch self {
            case .off: MacStrings.off
            case .login: MacStrings.connectAtLogin
            case .boot: MacStrings.connectAtBootBeforeLogin
            }
        }

        public init(options: MacProfileOptions) {
            self = options.startBeforeLogin ? .boot : (options.autoConnectAtLogin ? .login : .off)
        }

        public var profileOptions: MacProfileOptions {
            MacProfileOptions(startBeforeLogin: self == .boot, autoConnectAtLogin: self == .login)
        }
    }

    public struct MacPreferences: Codable, Equatable, Sendable {
        public var global: MacGlobalSettings = .defaults
        public var flags: FeatureFlags = .defaults
        public var onboardingComplete = false
        public var hideDockIcon = false
        public init() {}

        /// Missing keys retain their individual defaults when preferences gain new fields.
        public init(from decoder: any Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            global = (try? values.decodeIfPresent(MacGlobalSettings.self, forKey: .global)) ?? .defaults
            flags = (try? values.decodeIfPresent(FeatureFlags.self, forKey: .flags)) ?? .defaults
            onboardingComplete = try values.decodeIfPresent(Bool.self, forKey: .onboardingComplete) ?? false
            hideDockIcon = try values.decodeIfPresent(Bool.self, forKey: .hideDockIcon) ?? false
        }
    }

    public enum MacSettingsTab: String, CaseIterable, Identifiable, Sendable {
        case general, protection, network, service, diagnostics, about
        public var id: Self {
            self
        }

        /// The five pages in the unified window; legacy Network content is hosted by Protection.
        public static let sidebarPages: [Self] = [.general, .protection, .service, .diagnostics, .about]

        public var title: String {
            switch self {
            case .general: MacStrings.general
            case .protection: MacStrings.protection
            case .network: MacStrings.network
            case .service: MacStrings.backgroundServicePage
            case .diagnostics: MacStrings.logPage
            case .about: MacStrings.about
            }
        }

        public var symbol: String {
            switch self {
            case .general: "gearshape"
            case .protection: "shield"
            case .network: "network"
            case .service: "server.rack"
            case .diagnostics: "stethoscope"
            case .about: "info.circle"
            }
        }
    }

    /// First-run setup (SPEC 7): three sheets on the main window. The raw value is never persisted; it only numbers the
    /// progress dots.
    public enum MacOnboardingStep: Int, CaseIterable, Identifiable, Sendable {
        case welcome, backgroundService, addTunnel
        public static let ordered: [Self] = allCases
        public var id: Self {
            self
        }

        public var title: String {
            switch self {
            case .welcome: MacStrings.welcomeToWGEX
            case .backgroundService: MacStrings.allowWGEXInTheBackground
            case .addTunnel: MacStrings.addATunnelTitle
            }
        }

        public var message: String {
            switch self {
            case .welcome: MacStrings.wgexConnectsThisMacToYourOwnServer
            case .backgroundService: MacStrings.wgexKeepsYourTunnelRunning
            case .addTunnel: MacStrings.addATunnelMessage
            }
        }

        /// "Step 2 of 3", read by VoiceOver for the progress dots.
        public var progressLabel: String {
            OnboardingCopy.stepLabel(index: rawValue + 1, count: Self.allCases.count)
        }

        /// The word in step 2's Background service row: Needs approval, Starting…, Running or Unavailable.
        public static func serviceWord(state: ServiceState, running: Bool) -> String {
            switch state {
            case .notRegistered, .requiresApproval: MacStrings.needsApproval
            case .enabled: running ? MacStrings.running : MacStrings.startingEllipsis
            case .notFound: MacStrings.unavailable
            }
        }
    }

    public enum MacShellCopy {
        public static let hostGuard = MacStrings.hostGuardBackgroundService
    }
#endif
