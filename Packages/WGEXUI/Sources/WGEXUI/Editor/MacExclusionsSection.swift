// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// The Edit sheet's Exclusions section (DEC-087): one entry per line with Remove, then a field and Add with inline
    /// validation from the core, and the note that excluded traffic skips the tunnel and the kill switch.
    package struct MacExclusionsSection: View {
        @Bindable package var model: ProfileEditorModel
        @State private var input = ""

        package init(model: ProfileEditorModel) {
            self.model = model
        }

        package var body: some View {
            let validation = model.exclusionValidation(input)
            Section {
                ForEach(model.draft.exclusions, id: \.self) { entry in
                    HStack(spacing: 8) {
                        Text(entry).font(.body.monospaced()).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            .wgexAX(.editor, "exclusion", label: entry, item: entry)
                        Spacer(minLength: 8)
                        Button(MacStrings.removeExclusion, role: .destructive) { model.removeExclusion(entry) }
                            .wgexControl(
                                .editor, "removeExclusion", label: MacStrings.removeExclusionNamed(entry), item: entry,
                                inputLabel: MacStrings.removeExclusion,
                            )
                            .lineLimit(1).fixedSize()
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        TextField(MacStrings.exclusions, text: $input, prompt: Text(MacStrings.exclusionPlaceholder))
                            .labelsHidden().autocorrectionDisabled().lineLimit(1).font(.body.monospaced())
                            .onSubmit(add)
                            .wgexControl(.editor, "exclusionInput", label: MacStrings.exclusionPlaceholder)
                        Button(MacStrings.addExclusion, action: add)
                            .wgexControl(.editor, "addExclusion", label: MacStrings.addExclusion)
                            .lineLimit(1).fixedSize()
                            .disabled(validation != .valid)
                    }
                    if let message = validation.message {
                        Text(message).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                            .fixedSize(horizontal: false, vertical: true)
                            .wgexAX(.editor, "exclusionProblem", label: message)
                    }
                }
            } header: {
                Text(MacStrings.exclusions)
            } footer: {
                Text(MacStrings.exclusionsNote).font(.caption).foregroundStyle(MacDesign.label2)
                    .wgexAX(.editor, "exclusionsNote", label: MacStrings.exclusionsNote)
            }
        }

        private func add() {
            if model.addExclusion(input) {
                input = ""
            }
        }
    }
#endif
