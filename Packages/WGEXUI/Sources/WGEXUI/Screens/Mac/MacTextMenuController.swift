// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation

    /// Native menu only: disabled lines have no action or custom view. The timer runs during menu tracking.
    @MainActor
    public final class MacTextMenuController: NSObject, NSMenuDelegate {
        public let menu = NSMenu()
        private let model: MacShellModel
        private let now: () -> Date
        private let schedule: @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> () -> Void
        private let visibility: (Bool) -> Void
        private let perform: (MacMenuPresentation.Command) -> Void
        private var cancel: (() -> Void)?
        private var commands: [String: MacMenuPresentation.Command] = [:]
        public private(set) var isOpen = false

        public init(
            model: MacShellModel,
            now: @escaping () -> Date = Date.init,
            schedule: @escaping @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> () -> Void = MacTextMenuController.timer,
            visibility: @escaping (Bool) -> Void = { _ in },
            perform: @escaping (MacMenuPresentation.Command) -> Void,
        ) {
            self.model = model
            self.now = now
            self.schedule = schedule
            self.visibility = visibility
            self.perform = perform
            super.init()
            menu.autoenablesItems = false
            menu.delegate = self
            refresh()
        }

        public func menuWillOpen(_: NSMenu) {
            guard !isOpen else { return }
            isOpen = true
            visibility(true)
            refresh()
            cancel = schedule(MacSessionTraffic.samplingInterval) { [weak self] in
                guard let self, isOpen else { return }
                refresh()
            }
        }

        public func menuDidClose(_: NSMenu) {
            isOpen = false
            cancel?()
            cancel = nil
            visibility(false)
        }

        /// Also used on observation changes, without replacing items that may be highlighted.
        public func refresh() {
            model.tick(at: now())
            let rows = MacMenuPresentation(model: model).rows
            let ids = Set(rows.map(\.id))
            for item in menu.items where !ids.contains(item.identifier?.rawValue ?? "") {
                menu.removeItem(item)
            }
            commands = [:]
            for (index, row) in rows.enumerated() {
                let item: NSMenuItem
                if let existing = menu.items.first(where: { $0.identifier?.rawValue == row.id }) {
                    item = existing
                    if menu.index(of: item) != index {
                        menu.removeItem(item)
                        menu.insertItem(item, at: index)
                    }
                } else {
                    item = row.separator ? .separator() : NSMenuItem(title: row.title, action: nil, keyEquivalent: "")
                    item.identifier = NSUserInterfaceItemIdentifier(row.id)
                    menu.insertItem(item, at: index)
                }
                item.title = row.title
                item.isEnabled = row.enabled
                item.state = row.checked ? .on : .off
                item.indentationLevel = row.indentation
                item.target = row.command == nil ? nil : self
                item.action = row.command == nil ? nil : #selector(selected(_:))
                item.keyEquivalent = row.command == .quit ? "q" : ""
                item.keyEquivalentModifierMask = .command
                commands[row.id] = row.command
            }
        }

        @objc private func selected(_ item: NSMenuItem) {
            // Recheck fresh state: a command can have been queued just as the service disappeared.
            model.tick(at: now())
            let rows = MacMenuPresentation(model: model).rows
            guard let id = item.identifier?.rawValue,
                  let row = rows.first(where: { $0.id == id }), row.enabled,
                  let command = commands[id], row.command == command else { return }
            perform(command)
        }

        /// Main-run-loop timers continue in AppKit's nested event-tracking loop.
        public static func timer(interval: TimeInterval, fire: @escaping @MainActor () -> Void) -> () -> Void {
            let timer = Timer(timeInterval: interval, repeats: true) { _ in
                MainActor.assumeIsolated { fire() }
            }
            RunLoop.main.add(timer, forMode: .common)
            RunLoop.main.add(timer, forMode: .eventTracking)
            return { timer.invalidate() }
        }
    }
#endif

#if os(macOS) && DEBUG
    import SwiftUI

    /// Debug-only preview for the WGEXUITesting gallery; release builds carry only the live AppKit controller above.
    public struct MacMenuBarView: View {
        private let model: MacShellModel
        private let openWindow: () -> Void
        private let quit: () -> Void
        private let addProfile: () -> Void

        public init(
            model: MacShellModel,
            openWindow: @escaping () -> Void = {},
            quit: @escaping () -> Void = {},
            addProfile: @escaping () -> Void = {},
        ) {
            self.model = model
            self.openWindow = openWindow
            self.quit = quit
            self.addProfile = addProfile
        }

        public var body: some View {
            Menu(MacStrings.appName) {
                ForEach(MacMenuPresentation(model: model).rows, id: \.id) { row in
                    if row.separator {
                        Divider()
                    } else if let command = row.command {
                        Button(row.title) {
                            switch command {
                            case let .tunnel(id): Task { await model.toggleMenuTunnel(id) }
                            case .quit: quit()
                            case .importFile: addProfile()
                            case .about: model.routeWindow(.about); openWindow()
                            case .manage, .open: model.routeWindow(.manageTunnels); openWindow()
                            default: openWindow()
                            }
                        }.disabled(!row.enabled)
                    } else {
                        Text(row.title)
                    }
                }
            }
        }
    }
#endif
