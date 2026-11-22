// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import SwiftUI
    import WGEXCore

    /// Pure inputs of the app pages (SPEC 8): the Dock switch, the Background Service facts, the Log lines and the About
    /// version. Views read these; tests pin them without hosting a view.
    package enum MacAppPagesPresentation {
        // MARK: General

        /// "Show WGEX in the Dock" is the inverse of the stored Hide Dock icon preference.
        package static func showsDockIcon(_ model: MacShellModel) -> Binding<Bool> {
            Binding(get: { !model.preferences.hideDockIcon }, set: { model.preferences.hideDockIcon = !$0 })
        }

        // MARK: Background Service

        /// One fact row; `detail` is the small text under it and `action` the install button title.
        package struct Fact: Equatable, Identifiable {
            package let id: String
            package let label: String
            package let value: String
            package var detail: String?
            package var action: String?
        }

        /// Service, Allowed in System Settings and Installed in Applications (SPEC 8.3).
        package static func serviceFacts(state: ServiceState, running: Bool, install: SecureInstallState) -> [Fact] {
            [
                Fact(id: "service", label: MacStrings.serviceFact, value: serviceWord(state, running: running)),
                Fact(id: "allowed", label: MacStrings.allowedInSystemSettings, value: allowedWord(state)),
                installedFact(install),
            ]
        }

        private static func serviceWord(_ state: ServiceState, running: Bool) -> String {
            switch state {
            case .enabled: running ? MacStrings.running : MacStrings.serviceNotRunning
            case .requiresApproval: MacStrings.serviceWaitingForApproval
            case .notRegistered: MacStrings.serviceNotRegistered
            case .notFound: MacStrings.unavailable
            }
        }

        private static func allowedWord(_ state: ServiceState) -> String {
            switch state {
            case .enabled: MacStrings.factYes
            case .requiresApproval: MacStrings.factNo
            case .notRegistered, .notFound: MacStrings.unavailable
            }
        }

        private static func installedFact(_ install: SecureInstallState) -> Fact {
            let fact = Fact(id: "installed", label: MacStrings.installedInApplications, value: MacStrings.unavailable)
            return switch install {
            case .verified: Fact(id: fact.id, label: fact.label, value: MacStrings.installVerified)
            case .checking: Fact(id: fact.id, label: fact.label, value: MacStrings.installChecking)
            case .notReporting: fact
            case .needsAttention:
                Fact(
                    id: fact.id, label: fact.label, value: MacStrings.installNeedsAttention, detail: install.detail,
                    action: install.actionTitle,
                )
            }
        }

        /// What Register Again does: a first registration when nothing is registered, otherwise unregister and register.
        package enum RegisterAgain: Equatable {
            case register, reregister
        }

        package static func registerAgain(for state: ServiceState) -> RegisterAgain {
            state == .notRegistered || state == .notFound ? .register : .reregister
        }

        // MARK: Log

        /// The Events tab's category for an event (SPEC 8.4).
        package static func category(_ kind: TunnelEvent.Kind) -> String {
            TunnelEventLines.category(kind)
        }

        package typealias EventLine = TunnelEventLines.Line

        /// Every held event, oldest first (the newest at the bottom), at most the backend's 32, whatever is selected.
        package static func eventLines(_ events: [TunnelEvent]) -> [EventLine] {
            TunnelEventLines.lines(events)
        }

        /// The Events tab as saved: one line each, GMT timestamp, category and sentence.
        package static func eventsText(_ lines: [EventLine]) -> String {
            TunnelEventLines.text(lines)
        }

        /// Writes what the shown tab shows to the URL the user chose, and nowhere else.
        package static func saveLog(_ text: String, to url: URL) throws {
            try MacLogFile.write(text, to: url)
        }

        // MARK: About

        /// Info.plist key holding the public documentation address. The project defines none yet (SPEC G2), so About
        /// shows the link only once a build sets it.
        package static let documentationKey = "WGEXDocumentationURL"

        /// The configured documentation address: an absolute https URL with a host, or nil (no row).
        package static func documentationURL(_ info: [String: Any]?) -> URL? {
            guard let text = info?[documentationKey] as? String, let url = URL(string: text),
                  url.scheme?.lowercased() == "https", url.host()?.isEmpty == false else { return nil }
            return url
        }

        /// "Version 1.2 (45)", or today's Development fallback when the bundle has no version.
        package static func versionLine(_ info: [String: Any]?) -> String {
            AboutText.versionLine(info)
        }
    }
#endif
