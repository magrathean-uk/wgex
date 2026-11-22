// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import SwiftUI
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    /// M07-T05: the General, Protection, Background Service, Log and About pages (SPEC 8, E1, E6).
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacAppPagesTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let generation = Generation(rawValue: 1)

        private static let pageFiles = [
            "MacSettingsView.swift", "MacGeneralPage.swift", "MacProtectionPage.swift", "MacBackgroundServicePage.swift",
            "MacLogPage.swift", "MacAboutPage.swift",
        ]

        private func shell(_ protection: ProtectionState = .protected, events: [TunnelEvent] = []) -> MacShellModel {
            let profile = TunnelProfile(name: "Home")
            let phase: TunnelPhase = protection == .unprotected ? .idle : .active(generation)
            var status = TunnelStatus(phase: phase, protection: protection, transport: nil, health: .idle, recentEvents: events)
            status.activeProfileID = protection == .unprotected ? nil : profile.id
            status.measuredAt = date
            return MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [profile],
                status: status,
                now: date,
            )
        }

        // MARK: Copy

        @Test func `page copy is exactly the SPEC wording`() {
            let expected: [(String, String)] = [
                // General
                (MacStrings.defaultTunnel, "Default tunnel"),
                (MacStrings.chooseATunnel, "Choose a tunnel"),
                (MacStrings.showWGEXInTheDock, "Show WGEX in the Dock"),
                (MacStrings.notifyMeWhenProtectionChanges, "Notify me when protection changes"),
                (MacStrings.notificationDeliveryArrivesInA, "Notification delivery arrives in a later update."),
                (MacStrings.quittingDoesNotDisconnectTheTunnel, "Quitting WGEX does not deactivate the tunnel."),
                // Protection
                (MacStrings.killSwitch, "Kill switch"),
                (MacStrings.killSwitchNote, "Always on while a tunnel is active. Blocks all traffic if the tunnel drops."),
                (MacStrings.lockdown, "Lockdown"),
                (MacStrings.lockdownNote, "Keeps blocking even after a restart, until a tunnel is up."),
                (MacStrings.allowLocalNetwork, "Allow local network"),
                (MacStrings.allowLocalNetworkNote, "Printers, AirPlay and file sharing bypass the tunnel."),
                (MacStrings.signInWindow, "Sign-in window"),
                (MacStrings.signInWindowNote, "How long protection pauses for a Wi-Fi sign-in page."),
                (MacStrings.whatWGEXCannotProtect, "What WGEX cannot protect"),
                (MacStrings.limitSignInWindow, "During a sign-in window, traffic is unprotected."),
                (MacStrings.limitLocalNetwork, "Local traffic, when allowed, and traffic to exclusions bypass the tunnel."),
                (MacStrings.limitBeforeUnlock, "Before the disk is unlocked at start-up, WGEX is not running."),
                // Background Service
                (MacStrings.serviceFact, "Service"),
                (MacStrings.allowedInSystemSettings, "Allowed in System Settings"),
                (MacStrings.installedInApplications, "Installed in Applications"),
                (MacStrings.openLoginItemsSettings, "Open Login Items Settings…"),
                (MacStrings.registerAgain, "Register Again"),
                (MacStrings.finishUpdateEllipsis, "Finish Update…"),
                (MacStrings.uninstallGroup, "Uninstall"),
                (MacStrings.uninstallWGEXEllipsis, "Uninstall WGEX…"),
                (
                    MacStrings.uninstallFootnote,
                    "Removes the background service from this Mac. Before anything is removed, you choose whether to keep your tunnels.",
                ),
                // Log
                (MacStrings.logPage, "Log"),
                (MacStrings.logEvents, "Events"),
                (MacStrings.logRaw, "Raw"),
                (MacStrings.saveLog, "Save Log…"),
                (MacStrings.exportDiagnosticsEllipsis, "Export Diagnostics…"),
                (MacStrings.logFooter, "Newest at the bottom. Diagnostics exports never include private keys."),
                (MacStrings.noEventsSinceWGEXStarted, "No events since WGEX started."),
                (MacStrings.noLogLinesYet, "No log lines yet."),
                (MacStrings.theLogCouldNotBeSaved, "The log could not be saved."),
                // About
                (MacStrings.appName, "WGEX"),
                (MacStrings.mitLicence, "MIT licence"),
                (MacStrings.acknowledgementsCouldNotBeLoaded, "Acknowledgements could not be loaded."),
            ]
            for (actual, wanted) in expected {
                #expect(actual == wanted)
            }
            #expect(MacStrings.wireGuardTrademarkDisclaimer.hasPrefix("WireGuard is a registered trademark of Jason A. Donenfeld."))
        }

        @Test func `new page copy avoids the retired words`() {
            for text in MacStrings.appPagesCatalogue {
                for word in ["profile", "allow lan", "daemon", "helper", "captive"] {
                    #expect(!text.lowercased().contains(word), "\(text)")
                }
                #expect(!text.contains("—"))
            }
        }

        // MARK: General

        @Test func `the Dock switch shows the inverse of the stored hide flag`() {
            let model = shell()
            let dock = MacAppPagesPresentation.showsDockIcon(model)
            model.preferences.hideDockIcon = false
            #expect(dock.wrappedValue)
            dock.wrappedValue = false
            #expect(model.preferences.hideDockIcon)
            dock.wrappedValue = true
            #expect(!model.preferences.hideDockIcon)
        }

        @Test func `General has no start-up picker; start-up stays on the tunnel page`() throws {
            let general = try page("MacGeneralPage.swift")
            for marker in ["saveStartup", "startupOption", "MacStartupSettingsView", "connectAutomatically", "connectionAtStartup"] {
                #expect(!general.contains(marker))
            }
            #expect(general.contains("\"defaultTunnel\""))
            #expect(general.contains("$model.selectedProfileID"))
            #expect(general.contains("MacStrings.notificationDeliveryArrivesInA"))
        }

        @Test func `each app-wide setting is a control on one app page only`() throws {
            let sources = try Self.pageFiles.map(page).joined()
            for key in ["lockdown", "allowLAN", "captiveWindowSeconds", "notifications"] {
                #expect(sources.components(separatedBy: "globalSetting(\\.\(key))").count == 2, "\(key)")
            }
            let protection = try page("MacProtectionPage.swift")
            for key in ["lockdown", "allowLAN", "captiveWindowSeconds"] {
                #expect(protection.contains("globalSetting(\\.\(key))"))
            }
            #expect(try page("MacGeneralPage.swift").contains("globalSetting(\\.notifications)"))
            #expect(!sources.contains("revisitSetup"))
            #expect(!sources.contains("MacShellCopy.knownGaps"))
            #expect(!sources.contains("MacStrings.dns"))
            #expect(!sources.contains("MacStrings.mtu"))
        }

        // MARK: Protection

        @Test func `the Protection kill switch word follows protection and staleness`() throws {
            let cases: [(ProtectionState, String)] = [
                (.protected, "On"), (.blocked, "Blocking"), (.captiveWindow(expires: date.addingTimeInterval(60)), "Paused"),
                (.unprotected, "Off"), (.unsupported, "Unavailable"), (.unknown, "Unavailable"),
            ]
            for (protection, word) in cases {
                #expect(shell(protection).killSwitchWord(for: nil) == word, "\(protection)")
            }
            let stale = shell(.protected)
            stale.receiveConnection(.connected(daemonBuild: 42))
            stale.receive(stale.status, at: date)
            stale.receiveConnection(.disconnected(lastError: nil))
            #expect(stale.presentation.verdict == .stale)
            #expect(stale.killSwitchWord(for: nil) == "Unavailable")
            #expect(try page("MacProtectionPage.swift").contains("model.killSwitchWord(for: nil)"))
        }

        // MARK: Background Service

        @Test func `service facts read in plain words for every state`() {
            let services: [ServiceState: (stopped: String, running: String)] = [
                .enabled: ("Not running", "Running"), .requiresApproval: ("Waiting for approval", "Waiting for approval"),
                .notRegistered: ("Not registered", "Not registered"), .notFound: ("Unavailable", "Unavailable"),
            ]
            let allowed: [ServiceState: String] = [
                .enabled: "Yes", .requiresApproval: "No", .notRegistered: "Unavailable", .notFound: "Unavailable",
            ]
            let installed: [SecureInstallState: String] = [.verified: "Verified", .checking: "Checking…", .notReporting: "Unavailable"]
            for state in ServiceState.allCases {
                for running in [false, true] {
                    for install in SecureInstallState.all {
                        let facts = MacAppPagesPresentation.serviceFacts(state: state, running: running, install: install)
                        #expect(facts.map(\.label) == ["Service", "Allowed in System Settings", "Installed in Applications"])
                        #expect(facts[0].value == (running ? services[state]?.running : services[state]?.stopped))
                        #expect(facts[1].value == allowed[state])
                        if let word = installed[install] {
                            #expect(facts[2].value == word)
                            #expect(facts[2].detail == nil && facts[2].action == nil)
                        } else {
                            #expect(facts[2].value == "Needs attention")
                            #expect(facts[2].detail == install.detail)
                            #expect(facts[2].action == install.actionTitle)
                        }
                    }
                }
            }
        }

        @Test func `Register Again registers when nothing is registered and re-registers otherwise`() throws {
            #expect(MacAppPagesPresentation.registerAgain(for: .notRegistered) == .register)
            #expect(MacAppPagesPresentation.registerAgain(for: .notFound) == .register)
            #expect(MacAppPagesPresentation.registerAgain(for: .enabled) == .reregister)
            #expect(MacAppPagesPresentation.registerAgain(for: .requiresApproval) == .reregister)
            let source = try page("MacBackgroundServicePage.swift")
            #expect(source.contains("case .register: await model.registerService()"))
            #expect(source.contains("case .reregister: await model.reregisterService()"))
            #expect(source.contains("action: model.openApproval"))
            #expect(source.contains("if model.simulated, model.serviceState == .requiresApproval"))
            #expect(source.contains("if model.updateAvailable"))
            #expect(source.contains("if model.downgradeDetected"))
        }

        @Test func `Background Service ends with Uninstall on its own and opens the existing sheet`() throws {
            let source = try page("MacBackgroundServicePage.swift")
            let form = try #require(source.components(separatedBy: "Form {").dropFirst().first?.components(separatedBy: ".formStyle").first)
            #expect(form.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("uninstallSection\n            }"))
            let parts = source.components(separatedBy: "private var uninstallSection: some View {")
            try #require(parts.count == 2)
            let section = try #require(parts[1].components(separatedBy: "private func factRow(").first)
            #expect(section.contains("Text(MacStrings.uninstallGroup)"))
            #expect(section.contains("\"uninstallOpen\""))
            #expect(section.contains(".disabled(model.hostGuarded)\n"))
            #expect(section.contains("MacStrings.uninstallFootnote"))
            #expect(section.contains("presentsUninstall = true"))
            #expect(source.contains(".sheet(isPresented: $presentsUninstall) { MacUninstallSheet(uninstall: model.uninstall) }"))
            #expect(!source.contains("revisit"))
            #expect(!source.contains("MacStartupSettingsView"))
        }

        private func page(_ name: String) throws -> String {
            try pageSource(name)
        }
    }

    /// M07-T05: the Log and About pages (SPEC 8.4, 8.5, E6).
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacLogAndAboutPageTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)

        // MARK: Log

        @Test func `the Log page fills its page outside a form with its controls on the title line`() throws {
            let log = try page("MacLogPage.swift")
            #expect(!log.contains("Form {") && !log.contains(".formStyle"))
            let toolbar = log.components(separatedBy: ".toolbar {")
            try #require(toolbar.count == 2)
            let items = try #require(toolbar[1].components(separatedBy: ".task(id:").first)
            #expect(items.contains("Picker(MacStrings.eventsFormat"))
            #expect(items.contains(".pickerStyle(.segmented)"))
            #expect(items.contains("Button(MacStrings.saveLog"))
            #expect(items.contains(".disabled(shownIsEmpty)"))
            #expect(items.contains("MacDiagnosticsExportButton(model: model)"))
            #expect(log.contains("MacStrings.logFooter"))
            // Every held event, whatever the sidebar selection.
            #expect(log.contains("MacAppPagesPresentation.eventLines(model.status.recentEvents)"))
            #expect(!log.contains("selected"))
            let router = try page("MacSettingsView.swift")
            #expect(!router.contains("Form {") && !router.contains(".formStyle"))
            #expect(!router.contains("TabView"))
            #expect(!router.contains("showStatusInMenuBar"))
            #expect(!router.contains("operationMessage"))
            #expect(router.contains("content(model.settingsTab)"))
            #expect(router.contains("case .protection, .network: MacProtectionPage(model: model)"))
            #expect(router.contains("case .diagnostics: MacLogPage(model: model)"))
        }

        @Test func `events carry a category and list oldest first, at most 32`() {
            let kinds: [(TunnelEvent.Kind, String)] = [
                (.phaseChanged, "Tunnel"), (.failed(.timedOut), "Tunnel"),
                (.handshakeCompleted, "Server"), (.txWithoutRx, "Server"), (.endpointChanged, "Server"),
                (.protectionChanged(.blocked), "Protection"),
                (.transportChanged(nil), "Network"), (.pathChanged, "Network"),
            ]
            for (kind, category) in kinds {
                #expect(MacAppPagesPresentation.category(kind) == category)
            }
            #expect(MacAppPagesPresentation.eventLines([]).isEmpty)
            let events = (0 ..< 40)
                .map { TunnelEvent(date: date.addingTimeInterval(Double($0)), kind: .handshakeCompleted, generation: nil) }
            let lines = MacAppPagesPresentation.eventLines(events)
            #expect(lines.count == 32)
            #expect(lines.first?.date == date.addingTimeInterval(8))
            #expect(lines.last?.date == date.addingTimeInterval(39))
            #expect(lines.map(\.date) == lines.map(\.date).sorted())
            #expect(lines.allSatisfy { $0.category == "Server" && $0.sentence == EventDescription.describe(.handshakeCompleted).text })
        }

        @Test func `Save Log writes the shown Events lines only to the chosen file`() throws {
            let event = TunnelEvent(date: date, kind: .protectionChanged(.protected), generation: nil)
            let text = MacAppPagesPresentation.eventsText(MacAppPagesPresentation.eventLines([event]))
            #expect(text == "2027-01-15T08:00:00.000Z Protection \(EventDescription.protectionText(.protected))\n")
            let directory = FileManager.default.temporaryDirectory.appending(path: "wgex-pages-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let url = directory.appending(path: "log.txt")
            try MacAppPagesPresentation.saveLog(text, to: url)
            #expect(try String(contentsOf: url, encoding: .utf8) == text)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["log.txt"])
        }

        // MARK: About

        @Test func `About shows the version with its build and keeps the Development fallback`() {
            #expect(MacAppPagesPresentation
                .versionLine(["CFBundleShortVersionString": "1.2", "CFBundleVersion": "45"]) == "Version 1.2 (45)")
            #expect(MacAppPagesPresentation.versionLine(["CFBundleShortVersionString": "1.2"]) == "Version 1.2")
            #expect(MacAppPagesPresentation.versionLine(nil) == "Version Development")
            #expect(MacAppPagesPresentation.versionLine(["CFBundleVersion": "45"]) == "Version Development (45)")
        }

        @Test func `About links to the configured documentation address and hides the row without one`() throws {
            let key = MacAppPagesPresentation.documentationKey
            #expect(key == "WGEXDocumentationURL")
            let url = MacAppPagesPresentation.documentationURL([key: "https://docs.wgex.test/mac"])
            #expect(url?.absoluteString == "https://docs.wgex.test/mac")
            #expect(MacAppPagesPresentation.documentationURL(nil) == nil)
            #expect(MacAppPagesPresentation.documentationURL([:]) == nil)
            for invalid in ["", "docs", "http://docs.wgex.test", "file:///tmp/docs", "https://"] {
                #expect(MacAppPagesPresentation.documentationURL([key: invalid]) == nil, "\(invalid)")
            }
            #expect(MacStrings.documentationLink == "Documentation")
            let about = try page("MacAboutPage.swift")
            #expect(about.contains("if let documentation = MacAppPagesPresentation.documentationURL(Bundle.main.infoDictionary)"))
            #expect(about.contains("Link(destination: documentation)"))
            #expect(about.contains("\"documentation\""))
        }

        @Test func `About has no update controls`() throws {
            let about = try page("MacAboutPage.swift")
            #expect(!about.contains("finishUpdate"))
            #expect(about.contains("MacStrings.mitLicence"))
            #expect(about.contains("MacStrings.thanksToWireGuard"))
            #expect(about.contains("MacStrings.wireGuardTrademarkDisclaimer"))
            #expect(about.contains("Text(acknowledgements)"))
        }

        private func page(_ name: String) throws -> String {
            try pageSource(name)
        }
    }

    private func pageSource(_ name: String) throws -> String {
        let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appending(path: "Sources/WGEXUI/Screens/Mac/\(name)"), encoding: .utf8)
    }
#endif
