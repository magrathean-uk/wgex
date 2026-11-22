// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI
    import Testing
    import WGEXCore
    @testable import WGEXUI

    /// M07-T16: typing into the Mac Edit sheet keeps focus in the field. A row whose caption comes or goes with the text (the
    /// empty-name caption under Name and Addresses) must not replace its field, or every character after the first is lost.
    @MainActor
    private struct MacEditorTextEntryTests {
        private final class Host {
            let window: NSWindow
            init(_ view: some View) {
                _ = NSApplication.shared
                window = NSWindow(
                    contentRect: NSRect(x: 0, y: 0, width: 640, height: 900), styleMask: [.titled], backing: .buffered, defer: false,
                )
                window.isReleasedWhenClosed = false
                window.contentView = NSHostingView(rootView: view.frame(width: 640, height: 900))
                settle()
            }

            func settle() {
                window.contentView?.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.15))
                window.contentView?.layoutSubtreeIfNeeded()
            }

            /// Text fields top to bottom (AppKit is flipped in the hosting view's window coordinates the other way round).
            func textFields() -> [NSTextField] {
                func walk(_ view: NSView) -> [NSTextField] {
                    let own = (view as? NSTextField).map { $0.isEditable ? [$0] : [] } ?? []
                    return own + view.subviews.flatMap(walk)
                }
                guard let root = window.contentView else { return [] }
                return walk(root).sorted {
                    $0.convert($0.bounds, to: nil).maxY > $1.convert($1.bounds, to: nil).maxY
                }
            }

            /// Types into the focused field the way the keyboard does: through the field editor.
            func type(_ text: String) {
                for character in text {
                    (window.firstResponder as? NSTextView)?.insertText(
                        String(character),
                        replacementRange: NSRange(location: NSNotFound, length: 0),
                    )
                    settle()
                }
            }

            /// The text field that owns the current field editor, if it is still in the window.
            var focusedField: NSTextField? {
                guard let editor = window.firstResponder as? NSTextView, editor.isFieldEditor,
                      let field = editor.delegate as? NSTextField, field.window === window else { return nil }
                return field
            }
        }

        @Test func `typing a name into a new tunnel keeps every character and the focus`() throws {
            let model = ProfileEditorModel(allowsIncomplete: true)
            model.generateKeypair()
            let host = Host(MacTunnelEditForm(model: model, connectedNetwork: nil))
            defer { host.window.close() }
            let name = try #require(host.textFields().first, "the Name field is the first text field")
            #expect(host.window.makeFirstResponder(name))
            host.type("wgex")
            #expect(model.draft.name == "wgex", "every typed character lands in Name")
            #expect(host.focusedField != nil, "Name keeps the focus after the empty-name caption goes")
        }

        @Test func `typing an address after the name keeps every character`() throws {
            let model = ProfileEditorModel(allowsIncomplete: true)
            model.generateKeypair()
            model.draft.name = "wgex"
            let host = Host(MacTunnelEditForm(model: model, connectedNetwork: nil))
            defer { host.window.close() }
            let fields = host.textFields()
            let addresses = try #require(fields
                .first { $0.placeholderString == MacStrings.addresses || $0.placeholderAttributedString?.string == MacStrings.addresses })
            #expect(host.window.makeFirstResponder(addresses))
            host.type("10.250.0.2/32")
            #expect(model.draft.addresses == "10.250.0.2/32")
            #expect(host.focusedField != nil)
        }

        @Test func `Return in Edit as Text is a new line and does not save`() async throws {
            let parsed = try EditorFixtures.parsed("single-peer-full-tunnel")
            let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets, allowsIncomplete: true)
            model.draft.protection.ipv6Policy = .blockOutside // savable, so the control below can see Save
            var saves = 0
            let host = Host(MacTunnelEditSheet(model: model, onSave: { _, _ in saves += 1 }, onCancel: {}, opensAsText: true))
            defer { host.window.close() }
            host.window.setFrameOrigin(NSPoint(x: -20000, y: -20000))
            host.window.orderFrontRegardless()
            host.window.makeKey()
            host.settle()
            func walk(_ view: NSView) -> [NSTextView] {
                ((view as? NSTextView).map { $0.isFieldEditor ? [] : [$0] } ?? []) + view.subviews.flatMap(walk)
            }
            let textView = try #require(host.window.contentView.flatMap(walk)?.first, "Edit as Text shows its text view")
            #expect(host.window.makeFirstResponder(textView))
            textView.setSelectedRange(NSRange(location: 0, length: 0))
            let before = textView.string
            let returnKey = try #require(NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: host.window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r",
                isARepeat: false, keyCode: 36,
            ))
            NSApplication.shared.sendEvent(returnKey)
            host.settle()
            try await Task.sleep(for: .milliseconds(200))
            #expect(saves == 0, "Return in the text view does not press Save")
            #expect(textView.string == "\n" + before, "Return types a new line")
            // The same event reaches the default action when the text view is not focused, so the rig can see a stolen Return.
            #expect(host.window.makeFirstResponder(nil))
            NSApplication.shared.sendEvent(returnKey)
            host.settle()
            try await Task.sleep(for: .milliseconds(300))
            host.settle()
            #expect(saves == 1, "unfocused, Return presses Save (the rig sees the default action)")
        }
    }
#endif
