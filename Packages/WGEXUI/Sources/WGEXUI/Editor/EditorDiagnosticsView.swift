// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore

/// Severity-labelled messages; meaning never depends on colour. On iOS and macOS each message also takes the sheet's
/// error or caution colour.
public struct EditorDiagnosticsView: View {
    private let diagnostics: [ConfigDiagnostic]
    public init(_ diagnostics: [ConfigDiagnostic]) {
        self.diagnostics = diagnostics
    }

    public var body: some View {
        #if os(iOS)
            iosBody
        #else
            labelledBody
        #endif
    }

    #if os(iOS)
        /// Captions under the row: the severity word with its symbol on the first line, the message under it at the row's
        /// text edge, in the footer font.
        private var iosBody: some View {
            ForEach(Array(diagnostics.enumerated()), id: \.offset) { _, issue in
                VStack(alignment: .leading, spacing: 1) {
                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        Image(systemName: issue.severity == .error ? "xmark.octagon" : "exclamationmark.triangle")
                        Text(issue.severity == .error ? EditorStrings.errors : EditorStrings.warnings).bold()
                    }
                    Text(issue.message)
                    if let line = issue.line {
                        Text(EditorStrings.line(line))
                    }
                }
                .font(IOSDesign.footer)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .combine)
                .modifier(EditorSeverityTone(severity: issue.severity))
            }
        }
    #endif

    private var labelledBody: some View {
        ForEach(Array(diagnostics.enumerated()), id: \.offset) { _, issue in
            Label {
                VStack(alignment: .leading) {
                    Text(issue.severity == .error ? EditorStrings.errors : EditorStrings.warnings).font(.caption.bold())
                    Text(issue.message)
                    if let line = issue.line {
                        Text(EditorStrings.line(line)).font(.caption)
                    }
                }
            } icon: {
                Image(systemName: issue.severity == .error ? "xmark.octagon" : "exclamationmark.triangle")
            }
            .accessibilityElement(children: .combine)
            .modifier(EditorSeverityTone(severity: issue.severity))
        }
    }
}

/// The sheet's colour for a message: error or caution on iOS and macOS; tvOS keeps the system look.
private struct EditorSeverityTone: ViewModifier {
    let severity: ConfigDiagnostic.Severity

    func body(content: Content) -> some View {
        #if os(iOS)
            content.foregroundStyle(severity == .error ? IOSDesign.error : IOSDesign.caution)
        #elseif os(macOS)
            content.foregroundStyle(severity == .error ? MacDesign.error : MacDesign.caution)
        #else
            content
        #endif
    }
}

package struct EditorFieldBadge: View {
    package let model: ProfileEditorModel
    package let field: EditorField
    package var body: some View {
        #if os(iOS)
            EditorDiagnosticsView(model.diagnostics(for: field)).font(IOSDesign.footer)
        #elseif os(macOS)
            EditorDiagnosticsView(model.diagnostics(for: field)).font(MacDesign.caption)
        #else
            EditorDiagnosticsView(model.diagnostics(for: field)).font(.caption)
        #endif
    }
}
