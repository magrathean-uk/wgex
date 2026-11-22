// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Combine
    import SwiftUI
    import UniformTypeIdentifiers
    import WGEXCore

    /// SPEC 6.3 and D10: a key row of the Edit sheet. Hidden, it shows fixed-length dots (never the key's length) and no Show
    /// button; clicking the dots, or Space when they have focus, reveals the key. Clicking the revealed key again, or Space,
    /// hides it; while revealed, Paste replaces it with a valid key from the clipboard. It also hides when focus moves away,
    /// its window stops being key or is minimised, the sheet closes, the app is deactivated, or the model's key changes
    /// elsewhere (`resetToken`). The row keeps no copy of the key: it shows what the model holds, read only while revealed,
    /// and while hidden the key is in no accessibility label or value.
    package struct MacKeyRow: View {
        /// Which key the row edits; it chooses the row's identifier.
        package enum Key: Equatable {
            case privateKey
            case presharedKey(UUID)
        }

        private let title: String
        private let key: Key
        private let hasKey: Bool
        private let resetToken: Int
        private let load: () -> String?
        private let commit: (borrowing SecretBytes) throws -> Void
        @State private var revealed = false
        @State private var pasteFailed = false
        @FocusState private var focused: Bool

        /// `load` returns the key's text for display only; `commit` takes a pasted key that has already parsed.
        package init(
            _ title: String, key: Key, hasKey: Bool, resetToken: Int,
            load: @escaping () -> String?, commit: @escaping (borrowing SecretBytes) throws -> Void,
        ) {
            self.title = title; self.key = key; self.hasKey = hasKey; self.resetToken = resetToken
            self.load = load; self.commit = commit
        }

        package var body: some View {
            VStack(alignment: .trailing, spacing: 2) {
                HStack(spacing: 12) {
                    Text(title).lineLimit(1).layoutPriority(1)
                        .contentShape(.rect)
                        .onTapGesture { hide() }
                    Spacer(minLength: 12)
                    if revealed {
                        revealedKey
                    } else {
                        hiddenKey
                    }
                }
                if pasteFailed {
                    Text(MacStrings.clipboardHoldsNoKey).font(.caption).foregroundStyle(MacDesign.label2).lineLimit(1)
                }
            }
            .onChange(of: focused) { _, isFocused in
                if !isFocused {
                    hide()
                }
            }
            .onChange(of: resetToken) { hide() }
            .onDisappear { hide() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in hide() }
            .macOnWindowLeave { hide() }
        }

        private var hiddenKey: some View {
            identified(
                Button(action: reveal) {
                    Text(hasKey ? SecretRevealState.mask : MacStrings.noPresharedKey)
                        .font(.body.monospaced()).foregroundStyle(MacDesign.label2).lineLimit(1)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain),
                label: MacStrings.hidden(title),
            )
            .accessibilityAction(named: MacStrings.show) { reveal() }
        }

        private var revealedKey: some View {
            identified(
                Text(load() ?? MacStrings.noPresharedKey)
                    .font(.body.monospaced()).lineLimit(1).truncationMode(.middle).privacySensitive()
                    .contentShape(.rect)
                    .focusable(interactions: .edit)
                    .focused($focused)
                    .onAppear { focused = true }
                    .onTapGesture { hide() }
                    .onKeyPress(.space) {
                        hide()
                        return .handled
                    }
                    .onPasteCommand(of: [.plainText]) { _ in paste() },
                label: MacStrings.revealed(title),
            )
            .help(MacStrings.keyRowHelp)
            .accessibilityHint(MacStrings.keyRowHelp)
            .accessibilityAction(named: MacStrings.hide) { hide() }
        }

        /// The row's identifier: `wgex.editor.privateKey`, or `wgex.editor.presharedKey.<server id>`.
        @ViewBuilder private func identified(_ view: some View, label: String) -> some View {
            switch key {
            case .privateKey: view.wgexControl(.editor, "privateKey", label: label, inputLabel: title)
            case let .presharedKey(peer): view.wgexControl(.editor, "presharedKey", label: label, item: peer.uuidString, inputLabel: title)
            }
        }

        private func reveal() {
            pasteFailed = false
            revealed = true
        }

        private func hide() {
            revealed = false
            pasteFailed = false
        }

        private func paste() {
            pasteFailed = !MacKeyPaste.commit(NSPasteboard.general.string(forType: .string) ?? "", using: commit)
        }
    }

    /// A pasted key reaches the model only when it parses, so a bad paste never leaves the field in an error state and the
    /// row never shows anything but the model's key.
    package enum MacKeyPaste {
        /// Commits `text` (surrounding whitespace ignored) when it is a base64 WireGuard key; false, changing nothing, otherwise.
        package static func commit(_ text: String, using commit: (borrowing SecretBytes) throws -> Void) -> Bool {
            var value = text.trimmingCharacters(in: .whitespacesAndNewlines)
            do {
                return try value.withUTF8 { source in
                    let bytes = try SecretBytes(copying: UnsafeRawBufferPointer(source))
                    guard ProfileEditorModel.isKeyText(bytes) else { return false }
                    try commit(bytes)
                    return true
                }
            } catch { return false }
        }
    }

    package extension View {
        /// Runs `left` when this view's window resigns key, or it or its sheet parent is minimised or closes: the moments a
        /// revealed secret must go even though the app stays active (Settings, the menu bar menu, Cmd-M, Mission Control).
        func macOnWindowLeave(_ left: @escaping () -> Void) -> some View {
            background(MacWindowLeaveProbe(left: left))
        }
    }

    private struct MacWindowLeaveProbe: NSViewRepresentable {
        let left: () -> Void

        func makeNSView(context _: Context) -> Probe {
            Probe(left: left)
        }

        func updateNSView(_ view: Probe, context _: Context) {
            view.left = left
        }

        @MainActor
        final class Probe: NSView {
            var left: () -> Void

            init(left: @escaping () -> Void) {
                self.left = left
                super.init(frame: .zero)
            }

            required init?(coder: NSCoder) {
                nil
            }

            override func viewDidMoveToWindow() {
                super.viewDidMoveToWindow()
                let center = NotificationCenter.default
                center.removeObserver(self)
                guard let window else { return }
                for name in [NSWindow.didResignKeyNotification, NSWindow.willMiniaturizeNotification, NSWindow.willCloseNotification] {
                    center.addObserver(self, selector: #selector(leave), name: name, object: window)
                }
                if let parent = window.sheetParent {
                    for name in [NSWindow.willMiniaturizeNotification, NSWindow.willCloseNotification] {
                        center.addObserver(self, selector: #selector(leave), name: name, object: parent)
                    }
                }
            }

            @objc private func leave() {
                Task { @MainActor [weak self] in self?.left() }
            }

            deinit { NotificationCenter.default.removeObserver(self) }
        }
    }
#endif
