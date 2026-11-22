// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Foundation
    import Observation
    import WGEXCore
    import WGEXUI

    /// App-owned status item, independent of window lifetime and application activation.
    @MainActor
    public final class MacStatusItemController {
        private let model: MacAppModel
        private var item: NSStatusItem?
        private var controller: MacTextMenuController?
        private var observing = false
        private let activate: () -> Void

        public init(model: MacAppModel, activate: @escaping () -> Void = { NSApplication.shared.activate() }) {
            self.model = model
            self.activate = activate
        }

        public func start() {
            guard item == nil else { return }
            let controller = MacTextMenuController(model: model.shell, visibility: { [weak model] visible in
                model?.uiWork?.visibility(visible, surface: "menu")
            }, perform: { [weak self] in self?.perform($0) })
            self.controller = controller
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            item.menu = controller.menu
            self.item = item
            observing = true
            track()
            Task { [model] in
                await model.start()
                model.uiWork?.visibility(controller.isOpen, surface: "menu")
                controller.refresh()
            }
        }

        private func track() {
            guard observing else { return }
            withObservationTracking {
                let shell = model.shell
                item?.button?.image = MacStatusImage.make(for: shell.presentation.verdict)
                item?.button?.toolTip = MacMenuPresentation(model: shell).rows.first?.title
                item?.button?.setAccessibilityIdentifier("wgex.menu.statusItem")
                item?.button?.setAccessibilityLabel(MacMenuPresentation(model: shell).rows.first?.title)
                // Observed so a later queued open (an uninstall offer) runs; a no-op until a live view installs the action.
                model.dispatchPendingWindowOpens()
            } onChange: { [weak self] in
                Task { @MainActor in self?.track() }
            }
        }

        // swiftformat:disable:next redundantInternal
        internal func perform(_ command: MacMenuPresentation.Command) {
            switch command {
            case let .tunnel(id): Task { await model.shell.toggleMenuTunnel(id) }
            case .manage, .open: showMain()
            case .importFile:
                showMain()
                model.chooseImportFile()
            case .about:
                model.requestWindow(.about)
                activate()
            case .quit: model.shell.quit { NSApplication.shared.terminate(nil) }
            case .endSignIn: Task { await model.shell.closeCaptiveWindow() }
            case .signIn: confirmSignIn()
            }
        }

        private func showMain() {
            model.requestWindow(.manageTunnels)
            activate()
        }

        private func confirmSignIn() {
            guard model.shell.presentation.verdict == .blocked, model.shell.showsCaptiveButton, !model.shell.busy,
                  !model.shell.hostGuarded else { return }
            NSApplication.shared.activate()
            let alert = NSAlert()
            alert.messageText = MacStrings.menuSignInConfirmation
            alert.informativeText = MacStrings.menuSignInWarning + "\n" +
                CaptiveWindowCopy.message(remaining: Double(model.shell.preferences.global.captiveWindowSeconds))
            alert.addButton(withTitle: MacStrings.cancel)
            alert.addButton(withTitle: MacStrings.menuSignInConfirmation)
            let consent = alert.runModal()
            model.shell.tick(at: Date())
            guard consent == .alertSecondButtonReturn, model.shell.presentation.verdict == .blocked,
                  !model.shell.busy, model.shell.pendingAction == nil else { return }
            Task { await model.shell.openCaptiveWindow() }
        }
    }
#endif
