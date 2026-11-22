// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXTesting
    @testable import WGEXUI

    @MainActor
    private struct MacWindowShellTests {
        private let date = Date(timeIntervalSince1970: 1_800_000_000)
        private let home = TunnelProfile(name: "Home")
        private let cabin = TunnelProfile(name: "Cabin")

        private func model() -> MacShellModel {
            MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [home, cabin], status: .idle, now: date,
            )
        }

        @Test func `sidebar contains the five agreed settings pages in order`() {
            #expect(MacSettingsTab.sidebarPages.map(\.title) == ["General", "Protection", "Background Service", "Log", "About"])
            #expect(MacStrings.tunnels == "Tunnels")
            #expect(MacStrings.settingsTitle == "Settings")
            #expect(MacStrings.addTunnel == "Add Tunnel…")
        }

        @Test func `settings selection retains the selected tunnel and can return to a different tunnel`() {
            let shell = model()
            #expect(shell.windowSelection == .tunnel(home.id))
            for tab in MacSettingsTab.sidebarPages {
                shell.windowSelection = .settings(tab)
                #expect(shell.windowSelection == .settings(tab))
                #expect(shell.selectedProfileID == home.id)
            }
            shell.windowSelection = .tunnel(cabin.id)
            #expect(!shell.showsSettings)
            #expect(shell.selectedProfileID == cabin.id)
            shell.windowSelection = nil
            #expect(shell.windowSelection == .tunnel(cabin.id))
        }

        private func active(_ id: UUID) -> TunnelStatus {
            var status = TunnelStatus.idle
            status.phase = .active(Generation(rawValue: 1))
            status.protection = .protected
            status.activeProfileID = id
            return status
        }

        private func loaded(_ profiles: [TunnelProfile]) -> MacShellModel {
            let shell = MacShellModel(
                dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true),
                profiles: [], now: date,
            )
            shell.profiles = profiles
            shell.applyInitialTunnel()
            return shell
        }

        @Test func `window opens on the active tunnel once the first status report names it`() {
            let lab = TunnelProfile(name: "Lab")
            let shell = loaded([home, cabin, lab])
            #expect(shell.windowSelection == .tunnel(home.id))
            shell.receive(active(cabin.id), at: date)
            #expect(shell.windowSelection == .tunnel(cabin.id))
            // Later reports never move a window the user is reading; the next Manage Tunnels open does.
            shell.receive(active(lab.id), at: date)
            #expect(shell.selectedProfileID == cabin.id)
            shell.windowSelection = .settings(.about)
            shell.routeWindow(.manageTunnels)
            #expect(shell.windowSelection == .tunnel(lab.id))
        }

        @Test(arguments: [false, true])
        func `with no active tunnel the window opens on the default tunnel`(startUp: Bool) {
            var lab = TunnelProfile(name: "Lab")
            if startUp {
                lab.macOptions.startBeforeLogin = true
            } else {
                lab.macOptions.autoConnectAtLogin = true
            }
            let shell = loaded([home, cabin, lab])
            #expect(shell.selectedProfileID == lab.id)
            shell.receive(.idle, at: date)
            #expect(shell.selectedProfileID == lab.id)
            // An active tunnel still comes first.
            shell.receive(active(cabin.id), at: date)
            shell.routeWindow(.reopen)
            #expect(shell.selectedProfileID == cabin.id)
        }

        @Test func `with no active or default tunnel the first opens, and none gives the empty page`() {
            let shell = loaded([cabin, home])
            shell.receive(.idle, at: date)
            #expect(shell.windowSelection == .tunnel(cabin.id))
            let empty = loaded([])
            empty.receive(.idle, at: date)
            empty.routeWindow(.manageTunnels)
            #expect(empty.windowSelection == nil)
            #expect(empty.selectedProfileID == nil)
        }

        @Test func `settings pages remain available with no tunnels`() {
            let shell = model()
            shell.profiles = []
            shell.selectedProfileID = nil
            #expect(shell.windowSelection == nil)
            for tab in MacSettingsTab.sidebarPages {
                shell.windowSelection = .settings(tab)
                #expect(shell.windowSelection == .settings(tab))
            }
            shell.routeWindow(.manageTunnels)
            #expect(!shell.showsSettings)
            #expect(shell.windowSelection == nil)
        }

        @Test func `unavailable tunnels and retired Network page cannot change selection`() {
            let shell = model()
            shell.windowSelection = .settings(.general)
            shell.windowSelection = .tunnel(UUID())
            #expect(shell.windowSelection == .settings(.general))
            shell.windowSelection = .settings(.network)
            #expect(shell.windowSelection == .settings(.general))
            shell.busy = true
            shell.windowSelection = .tunnel(cabin.id)
            #expect(shell.windowSelection == .settings(.general))
            // Settings remains navigable while a tunnel operation is in progress.
            shell.windowSelection = .settings(.about)
            #expect(shell.windowSelection == .settings(.about))
            shell.busy = false
            shell.windowSelection = .tunnel(cabin.id)
            #expect(shell.windowSelection == .tunnel(cabin.id))
            print("Negative navigation: FAIL rejected missing tunnel, busy tunnel selection and retired Network page; retry passed")
        }

        @Test func `inactive tunnels have no annotation even when another tunnel is active`() {
            let shell = model()
            #expect(shell.sidebarState(home) == nil)
            #expect(shell.sidebarState(cabin) == nil)
            var status = TunnelStatus.idle
            status.phase = .active(.init(rawValue: 1))
            status.protection = .protected
            status.activeProfileID = home.id
            shell.receive(status, at: date)
            #expect(shell.sidebarState(home) == "Active")
            #expect(shell.sidebarState(cabin) == nil)
            shell.windowSelection = .tunnel(cabin.id)
            #expect(shell.sidebarState(home) == "Active")
            #expect(shell.sidebarState(cabin) == nil)
            shell.tick(at: date.addingTimeInterval(30))
            #expect(shell.sidebarState(home) == MacStrings.menuUnknown)
            shell.receive(.idle, at: date)
            #expect(shell.sidebarState(home) == nil)
        }

        @Test func `pending start and each active state use words`() {
            let shell = model()
            let generation = Generation(rawValue: 1)
            let cases: [(TunnelPhase, ProtectionState, String)] = [
                (.preparing(generation), .blocked, MacStrings.menuActivating),
                (.reasserting(generation, reason: .wake), .blocked, MacStrings.menuReconnecting),
                (.failed(.timedOut, blockedByPolicy: true, needsSecrets: false), .blocked, MacStrings.sidebarBlocked),
                (
                    .captiveWindow(generation, expires: date.addingTimeInterval(60)),
                    .captiveWindow(expires: date.addingTimeInterval(60)),
                    MacStrings.unprotected,
                ),
                (.active(generation), .unknown, MacStrings.menuUnknown),
            ]
            for (phase, protection, expected) in cases {
                var status = TunnelStatus.idle
                status.phase = phase
                status.protection = protection
                status.activeProfileID = home.id
                shell.receive(status, at: date)
                #expect(shell.sidebarState(home) == expected)
                #expect(shell.sidebarState(cabin) == nil)
            }
            shell.pendingAction = .connecting(cabin.id)
            #expect(shell.sidebarState(cabin) == MacStrings.menuActivating)
            shell.pendingAction = nil
            #expect(shell.sidebarState(cabin) == nil)
        }

        @Test func `loading profiles applies the SPEC 5.1 destination instead of the first tunnel`() throws {
            let app = try source("Apps/WGEXMac/MacAppModel.swift")
            #expect(app.contains("shell.profiles = profiles\n                shell.applyInitialTunnel()"))
        }

        @Test func `one scene owns all pages and setup is a sheet`() throws {
            let app = try source("Apps/WGEXMac/WGEXMacApp.swift")
            #expect(try sceneViolations(app).isEmpty)
            #expect(app.contains("Binding(get: { model.shell.showsOnboarding }, set: { model.shell.showsOnboarding = $0 })"))
            #expect(!app.contains("openSettings"))
            #expect(!app.contains("dismissWindow"))
            #expect(app.contains("CommandGroup(replacing: .appSettings)"))
            #expect(app.contains(".keyboardShortcut(\",\")"))
            #expect(app.contains("model.presentInitialOnboarding()"))
            #expect(app.contains("model.shell.showsOnboarding = false"))
            #expect(app.contains("model.shell.routeWindow(.manageTunnels)"))
            // Setup step 3 hands its Add actions to the window once the setup sheet has gone: no sheet on a sheet.
            #expect(app.contains("onDismiss: model.setupSheetDismissed"))
            #expect(!app.contains("importHostIsOnboarding") && !app.contains("editorHostIsOnboarding"))
            for fixture in ["", app + "\nSettings { }", app + "\nWindow(\"Setup\", id: \"onboarding\") {}", app + "\nWindowGroup {}"] {
                #expect(try !sceneViolations(fixture).isEmpty)
            }
            print("Negative scene fixtures: FAIL rejected extra Settings, setup Window and WindowGroup scenes")
        }

        @Test func `sidebar has text states and a sole footer action`() throws {
            let status = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacStatusViews.swift")
            let sidebar = try #require(status.components(separatedBy: "private var sidebar: some View {").last)
            // Layout A: text section headings drawn by MacSidebarHeading (DESIGN-MAC-1).
            #expect(sidebar.contains("MacSidebarHeading(MacStrings.tunnels)"))
            #expect(sidebar.contains("MacSidebarHeading(MacStrings.settingsTitle)"))
            #expect(sidebar.contains("ForEach(MacSettingsTab.sidebarPages)"))
            #expect(sidebar.contains("if let state = model.sidebarState(profile)"))
            #expect(!sidebar.contains("StateDot"))
            #expect(!sidebar.contains("ProgressView"))
            #expect(!sidebar.contains("EndpointText"))
            let footer = try #require(sidebar.components(separatedBy: "                Divider()").last)
            #expect(footer.components(separatedBy: "Button(").count == 2)
            #expect(footer.contains("Button(MacStrings.addTunnel, action: addProfile)"))
            // SPEC 5.1: no toolbar buttons; Export All stays in the app menu.
            // Hiding the toolbar title for layout A's in-page title adds no toolbar item.
            #expect(!status.contains(".toolbar {"))
            #expect(status.components(separatedBy: ".toolbar").count == status.components(separatedBy: ".toolbar(removing: .title)").count)
            #expect(!status.contains("ToolbarItem"))
            #expect(!status.contains(".navigationSubtitle"))
        }

        @Test func `commands and service links are wired to unified navigation`() throws {
            let app = try source("Apps/WGEXMac/WGEXMacApp.swift")
            for entry in ["about", "settings", "setup", "importTunnel", "manageTunnels"] {
                #expect(app.contains("show(.\(entry))"))
            }
            #expect(app.contains("model.requestWindow(entry) { openWindow(id: \"main\") }"))
            #expect(app.contains("\"exportAllCommand\""))
            // The App struct never reads openWindow from its own environment; a command view, built with the main menu
            // at launch, installs its live action for the status item and the launch decision.
            let appStruct = try #require(app.components(separatedBy: "public init()").first)
            #expect(!appStruct.contains("openWindow"))
            let commands = try #require(app.components(separatedBy: "private struct MacAppCommands: View {").last)
            #expect(commands.contains("let _ = model.installWindowOpener { [openWindow] in"))
            let menu = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacTextMenuController.swift")
            #expect(menu.contains("#if os(macOS) && DEBUG\n    import SwiftUI\n"), "The SwiftUI menu preview is debug-only")
            let statusItem = try source("Apps/WGEXMac/MacStatusItemController.swift")
            #expect(statusItem.contains("model.requestWindow(.about)\n"))
            #expect(statusItem.contains("model.requestWindow(.manageTunnels)\n"))
            #expect(statusItem.contains("model.dispatchPendingWindowOpens()\n"))
            let page = try source("Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacTunnelPage.swift")
            #expect(page.contains("model.windowSelection = .settings(.service)"))
            #expect(page.contains("model.windowSelection = .settings(.protection)"))
            #expect(!page.contains("openSettings"))
            let debug = try source("Apps/WGEXMac/DebugUI/MacDebugView.swift")
            #expect(debug.contains("model.requestWindow(.reopen) { openWindow(id: \"main\") }"))
            #expect(!debug.contains("openWindow(id: \"debug\")"))
        }

        private func sceneViolations(_ source: String) throws -> [String] {
            let pattern = #"\b(?:Window|WindowGroup|Settings)\s*(?:\(|\{)"#
            let declarations = try source.matches(of: Regex(pattern)).map { String($0.output[0].substring ?? "") }
            return declarations == ["Window("] ? [] : ["Expected one Window scene"] + declarations
        }

        private func source(_ path: String) throws -> String {
            let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            return try String(contentsOf: root.appending(path: path), encoding: .utf8)
        }
    }

    /// SPEC 5.1 destination: selections the rule must keep.
    extension MacWindowShellTests {
        @Test private func `a tunnel picked in the sidebar is kept on later opens and a command in flight is not re-targeted`() {
            let lab = TunnelProfile(name: "Lab")
            let shell = loaded([home, cabin, lab])
            shell.windowSelection = .tunnel(lab.id)
            shell.receive(active(cabin.id), at: date)
            shell.routeWindow(.manageTunnels)
            shell.routeWindow(.reopen)
            #expect(shell.selectedProfileID == lab.id)
            let busy = loaded([home, cabin])
            busy.busy = true
            busy.receive(active(cabin.id), at: date)
            busy.routeWindow(.manageTunnels)
            #expect(busy.selectedProfileID == home.id)
            // A selection made by an action rather than the rule (an import, a menu start) is not replaced either.
            let imported = loaded([home, cabin, lab])
            imported.selectedProfileID = lab.id
            imported.receive(active(cabin.id), at: date)
            imported.routeWindow(.manageTunnels)
            #expect(imported.selectedProfileID == lab.id)
        }
    }
#endif
