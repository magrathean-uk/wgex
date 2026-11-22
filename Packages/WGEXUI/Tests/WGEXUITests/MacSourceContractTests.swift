// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXUI

private struct MacSourceContractTests {
    @Test func `captive confirmation controls are catalogued`() throws {
        let ids = Set(WGEXAccessibility.catalogue.map(\.id))
        for element in ["cancelCaptiveWindow", "confirmCaptiveWindow"] {
            #expect(ids.contains("wgex.protection.\(element)"))
        }
        let confirmation = try String(contentsOf: root.appending(path:
            "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacCaptiveConfirmation.swift"), encoding: .utf8)
        #expect(confirmation.components(separatedBy: ".sheet(isPresented:").count == 2)
        #expect(confirmation.contains(".onChange(of: model.showsCaptiveButton)"))
        #expect(confirmation.contains("\"cancelCaptiveWindow\""))
        #expect(confirmation.contains("\"confirmCaptiveWindow\""))
        #expect(MacStrings.confirmOpenCaptiveWindow == "Open Sign-In Window")
        #expect(MacStrings.openCaptiveWindow == "Open Sign-In Window…")
        let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
        let page = try String(contentsOf: directory.appending(path: "MacTunnelPage.swift"), encoding: .utf8)
        #expect(page.contains(".macCaptiveConfirmation(model:"))
        let window = try String(contentsOf: directory.appending(path: "MacStatusViews.swift"), encoding: .utf8)
        #expect(!window.contains(".macCaptiveConfirmation(model:"))
        for source in [page, window] {
            #expect(!source.contains("await model.openCaptiveWindow()"))
            #expect(!source.contains(".sheet(isPresented:"))
        }
    }

    @Test func `sidebar values expose profile names`() throws {
        let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
        let status = try String(contentsOf: directory.appending(path: "MacStatusViews.swift"), encoding: .utf8)
        #expect(status.contains(".accessibilityValue(profile.name)"))
        #expect(status.components(separatedBy: ".accessibilityValue(profile.name)").count == 2)
        #expect(status.components(separatedBy: "inputLabel: profile.name").count == 2)
        #expect(status.components(separatedBy: "label: MacStrings.profileRowLabel(").count == 2)
        let ids = Set(WGEXAccessibility.catalogue.map(\.id))
        #expect(!ids.contains { $0.hasPrefix("wgex.session.") })
        #expect(!ids.contains("wgex.events.eventsFormat"))
    }

    @Test func `captive sheets and their flags belong to stable hosts rather than conditional controls`() throws {
        let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
        let page = try String(contentsOf: directory.appending(path: "MacTunnelPage.swift"), encoding: .utf8)
        #expect(page.components(separatedBy: "@State private var confirmsCaptiveWindow").count == 2)
        #expect(page.components(separatedBy: ".macCaptiveConfirmation(model:").count == 2)
        // The sheet hangs on the page's form, not on the conditional sign-in row that sets the flag.
        let parts = page.components(separatedBy: "private func extraRow(")
        try #require(parts.count == 2)
        #expect(parts[0].contains(".macCaptiveConfirmation(model: model, isPresented: $confirmsCaptiveWindow)"))
        #expect(parts[1].contains("confirmsCaptiveWindow = true"))
        #expect(!parts[1].contains(".macCaptiveConfirmation(model:"))
    }

    @Test func `inactive profile labels remain distinct in the VoiceOver item chooser`() {
        let home = MacStrings.profileRowLabel("Home", state: MacStrings.inactive)
        let cabin = MacStrings.profileRowLabel("Cabin", state: MacStrings.inactive)
        #expect(home == "Home, Inactive")
        #expect(cabin == "Cabin, Inactive")
        #expect(home != cabin)
    }

    @Test func `recovery and reporter detail text keeps its full vertical size`() throws {
        var details = 0
        let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac")
        for file in ["MacTunnelPage.swift", "MacStatusViews.swift"] {
            let source = try String(contentsOf: directory.appending(path: file), encoding: .utf8)
            let lines = source.components(separatedBy: .newlines)
            for index in lines.indices where lines[index].contains("Text(reason)") || lines[index].contains("Text(reporter)") {
                details += 1
                #expect(lines[index ..< min(index + 3, lines.count)].joined().contains(".fixedSize(horizontal: false, vertical: true)"))
            }
        }
        #expect(details == 2)
    }

    private var root: URL {
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    @Test func `fake backend selection is compiled only for Debug or Lab`() throws {
        let path = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI/Screens/Mac/MacShellDependencies.swift")
        let source = try String(contentsOf: path, encoding: .utf8)
        var conditions: [String] = []
        var selectors = 0
        for line in source.components(separatedBy: .newlines) {
            let text = line.trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("#if ") {
                conditions.append(String(text.dropFirst(4)))
            } else if text == "#else", let condition = conditions.popLast() {
                conditions.append("!(\(condition))")
            } else if text == "#endif" {
                _ = conditions.popLast()
            } else if text.contains("-WGEXFakeBackend") {
                selectors += 1
                #expect(conditions.contains("DEBUG || WGEX_LAB_BUILD"))
            }
        }
        #expect(selectors == 1)
    }

    @Test func `catalogue has unique camelCase identifiers for every screen`() {
        let catalogue = WGEXAccessibility.catalogue
        #expect(Set(catalogue.map(\.id)).count == catalogue.count)
        for screen in WGEXAccessibility.Screen.allCases {
            #expect(catalogue.contains { $0.screen == screen })
        }
        for entry in catalogue {
            #expect(entry.id.hasPrefix("wgex.\(entry.screen.rawValue)."))
            #expect(entry.id.wholeMatch(of: /wgex\.[a-z][a-zA-Z]*\.[a-z][a-zA-Z0-9]*/) != nil)
            #expect(!entry.id.hasSuffix("2"))
        }
        #expect(catalogue.filter { $0.id.hasSuffix(".orb") }.map(\.id) == ["wgex.connection.orb"])
    }

    @Test func `view identifiers and catalogue cover each other`() throws {
        var used = Set<String>()
        for url in try sources() where !url.path.contains("/Presentation/") {
            let source = try String(contentsOf: url, encoding: .utf8)
            let calls = try NSRegularExpression(pattern: #"\.wgex(?:AX|Control)\(\s*\.([A-Za-z]+),\s*"([^\"]+)""#)
            for match in calls.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                let screen = try String(source[#require(Range(match.range(at: 1), in: source))])
                let element = try String(source[#require(Range(match.range(at: 2), in: source))])
                used.insert("wgex.\(screen).\(element)")
            }
            let direct = try NSRegularExpression(pattern: #"accessibilityIdentifier\("([^"\n]+)""#)
            for match in direct.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                let identifier = try String(source[#require(Range(match.range(at: 1), in: source))])
                used.insert(identifier.components(separatedBy: ".\\(").first ?? identifier)
            }
            let menu = try NSRegularExpression(pattern: #"menuButton\([^\n]*element: "([A-Za-z]+)""#)
            for match in menu.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                try used.insert("wgex.menu." + source[#require(Range(match.range(at: 1), in: source))])
            }
        }
        // The AppKit status item sets its identifier in the app target.
        let statusItem = try String(contentsOf: root.appending(path: "Apps/WGEXMac/MacStatusItemController.swift"), encoding: .utf8)
        for match in statusItem.matches(of: /setAccessibilityIdentifier\("([^"\n]+)"\)/) {
            used.insert(String(match.output.1))
        }
        let catalogue = Set(WGEXAccessibility.catalogue.map(\.id))
        #expect(used.subtracting(catalogue).isEmpty, "Missing from catalogue: \(used.subtracting(catalogue).sorted())")
        // No exemptions: retired controls (the SwiftUI menu, the old Settings and Diagnostics buttons) leave the catalogue.
        let unused = catalogue.subtracting(used)
        #expect(unused.isEmpty, "Unused: \(unused.sorted())")
    }

    @Test func `Mac screens have no Text literals outside the copy catalogue`() throws {
        for url in try sources() where url.path.contains("/Screens/Mac/") {
            let source = try String(contentsOf: url, encoding: .utf8)
            #expect(source.range(of: #"\bText\(\s*\""#, options: .regularExpression) == nil, "Literal copy in \(url.lastPathComponent)")
        }
    }

    @Test func `every static string is enumerated and catalogue names describe their purpose`() throws {
        let files = try sources().filter { $0.lastPathComponent.contains("Strings+") && !$0.lastPathComponent.contains("Coverage") }
        var count = 0
        for url in files {
            let source = try String(contentsOf: url, encoding: .utf8)
            #expect(!source.contains("/// UI copy."))
            #expect(source.range(of: #"\bvalue[0-9]+\b"#, options: .regularExpression) == nil)
            let declarations = try NSRegularExpression(pattern: #"static let ([A-Za-z0-9]+) ="#)
            for match in declarations.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                let name = try String(source[#require(Range(match.range(at: 1), in: source))])
                #expect(name.range(of: #"[23]$"#, options: .regularExpression) == nil, "Numbered copy key: \(name)")
                count += 1
            }
        }
        #expect(count == MacStrings.catalogue.count + PlatformStrings.catalogue.count)
    }

    private func sources() throws -> [URL] {
        let directory = root.appending(path: "Packages/WGEXUI/Sources/WGEXUI")
        let enumerator = try #require(FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil))
        var urls = enumerator.compactMap { $0 as? URL }.filter {
            $0.pathExtension == "swift" && !$0.path.contains("/Previews/") && !$0.path.contains("/Screens/iOS/") && !$0.path
                .contains("/Screens/TV/")
        }
        urls.append(root.appending(path: "Apps/WGEXMac/WGEXMacApp.swift"))
        return urls
    }
}
