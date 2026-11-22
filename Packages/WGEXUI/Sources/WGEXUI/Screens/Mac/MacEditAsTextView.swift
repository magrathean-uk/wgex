// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// Edit as Text (SPEC 6.3, E7): the tunnel's WireGuard file, keys included, in a monospaced editor. The sheet owns the
    /// buffer and drops it on return to the form, on close and on app deactivation; nothing here stores or logs it.
    package struct MacEditAsTextView: View {
        @Binding private var text: String

        package init(text: Binding<String>) {
            _text = text
        }

        package var body: some View {
            TextEditor(text: $text)
                .font(MacDesign.body.monospaced())
                .foregroundStyle(MacDesign.text)
                .autocorrectionDisabled()
                .privacySensitive()
                .scrollContentBackground(.hidden)
                .padding(.vertical, MacDesign.Space.rowVertical + 3).padding(.horizontal, MacDesign.Space.rowHorizontal - 4)
                .macCard(padding: 0)
                .wgexControl(.editor, "configurationText", label: MacStrings.editAsText)
        }
    }

    /// The Edit as Text state of one Edit sheet: the buffer, its problems, and a notice that outlives the text view. Every way
    /// out of the text view (Edit as Form, Save, close, app or window deactivation) drops the buffer; text that parses is
    /// kept in the form, and text the app had to drop unparsed is announced instead of vanishing.
    package struct MacTextSession {
        package private(set) var isActive = false
        /// The editor's buffer; holds the keys only while `isActive`.
        package var text = ""
        package private(set) var entry = ""
        /// Shown while the text view is open: why the text does not parse, or why Save is blocked.
        package private(set) var problems: [String] = []
        /// Shown in either view until the next Edit as Text or Save: warnings kept from applied text, or the text dropped.
        package private(set) var notice: [String] = []

        package init() {}

        /// The buffer differs from what Edit as Text opened with.
        package var isEdited: Bool {
            isActive && text != entry
        }

        /// Opens the text view on the model's current tunnel.
        package mutating func open(_ model: ProfileEditorModel) throws {
            text = try model.configurationTextForEditing()
            entry = text
            problems = []
            notice = []
            isActive = true
        }

        /// Applies the buffer to the model; false, with the problem listed, when it does not parse.
        package mutating func apply(to model: ProfileEditorModel) -> Bool {
            var bytes = Array(text.utf8)
            do {
                problems = try MacTunnelProblems.lines(model.applyConfigurationText(&bytes))
                return true
            } catch {
                problems = MacTextProblems.lines(error)
                return false
            }
        }

        /// Edit as Form: back to the form only when the text parses; otherwise the text view stays and lists the problem.
        package mutating func returnToForm(_ model: ProfileEditorModel) -> Bool {
            guard apply(to: model) else { return false }
            notice = problems
            close()
            return true
        }

        /// The app or the window went away: text that parses is kept in the form; text that does not is dropped and said so.
        package mutating func leave(_ model: ProfileEditorModel) {
            guard isActive else { return }
            notice = apply(to: model) ? problems : [MacStrings.textChangesDiscarded] + problems
            close()
        }

        /// Save from the text view was refused by the model's own checks: list them under the text.
        package mutating func saveBlocked(_ model: ProfileEditorModel) {
            problems += MacTunnelProblems.lines(model.diagnostics.map(\.diagnostic), nameIsEmpty: model.draft.name.isEmpty)
        }

        /// A save went through: nothing is left to announce.
        package mutating func saved() {
            notice = []
            close()
        }

        /// Drops the buffer and leaves the text view.
        package mutating func close() {
            text = ""
            entry = ""
            isActive = false
        }
    }

    /// Plain-word lines for text that does not parse: a lead line, then each parser problem with its line number.
    package enum MacTextProblems {
        package static func lines(_ error: ConfigParseError) -> [String] {
            switch error {
            case .invalidUTF8: return [MacStrings.textIsNotAConfiguration, EditorStrings.invalidUTF8]
            case let .diagnostics(issues):
                let details = issues.filter { $0.severity == .error }.map { issue in
                    let text = MacTunnelProblems.text(issue)
                    return issue.line.map { MacStrings.line(String($0)) + ": " + text } ?? text
                }
                return [MacStrings.textIsNotAConfiguration] + details
            }
        }
    }
#endif
