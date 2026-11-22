// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore

/// Reveal-once state of a ``SecretField``: masked, revealed, then spent
/// (masked for good until the field is shown again).
public nonisolated struct SecretRevealState: Sendable, Hashable {
    /// Phase.
    public enum Phase: String, CaseIterable, Sendable, Hashable {
        /// Masked; one reveal available.
        case masked
        /// Showing the secret.
        case revealed
        /// Masked; the reveal was used.
        case spent
    }

    /// Fixed-length mask, so the mask does not reveal the secret's length.
    public static let mask = String(repeating: "•", count: 12)

    /// Current phase.
    public private(set) var phase: Phase = .masked

    /// Creates a masked state.
    public init() {}

    /// Whether a reveal is still available.
    public var canReveal: Bool {
        phase == .masked
    }

    /// Reveals once; false when the reveal was already used.
    @discardableResult
    public mutating func reveal() -> Bool {
        guard canReveal else { return false }
        phase = .revealed
        return true
    }

    /// Masks again; a revealed secret becomes spent.
    public mutating func hide() {
        if phase == .revealed {
            phase = .spent
        }
    }
}

/// A masked secret with a single reveal and a policy-governed copy action.
/// The secret is loaded only on reveal or copy and dropped on hide.
public struct SecretField: View {
    private let title: String
    private let loadSecret: () -> String?
    private let copier: SecretCopyController?
    private let onCommit: ((borrowing SecretBytes) throws -> Void)?
    /// iOS: more key buttons on the action row after Update key (Generate, Remove preshared key).
    private let moreActions: AnyView?
    @Environment(\.scenePhase) private var scenePhase
    private enum Focus: Hashable { case value, input, commit }
    @FocusState private var focus: Focus?
    @State private var editText = ""
    @State private var editFailed = false

    @State private var reveal = SecretRevealState()
    @State private var revealedText: String?

    /// Creates a field. `loadSecret` is called only when the user reveals or copies. On iOS `moreActions` (buttons that
    /// change the key, such as Generate) join Update key on its action row; other platforms ignore them.
    public init(
        _ title: String,
        copier: SecretCopyController? = nil,
        onCommit: ((borrowing SecretBytes) throws -> Void)? = nil,
        moreActions: AnyView? = nil,
        loadSecret: @escaping () -> String?,
    ) {
        self.onCommit = onCommit
        self.moreActions = moreActions
        self.title = title
        self.copier = copier
        self.loadSecret = loadSecret
    }

    /// For previews and design pictures only: the field as it looks with its one reveal in use, showing `text`.
    public func previewRevealed(_ text: String) -> SecretField {
        var field = self
        var state = SecretRevealState()
        state.reveal()
        field._reveal = State(initialValue: state)
        field._revealedText = State(initialValue: text)
        return field
    }

    /// The view body.
    public var body: some View {
        content
            .onDisappear { clearBuffers() }
            .onChange(of: scenePhase) {
                _, phase in if phase != .active {
                    clearBuffers()
                }
            }
            .onChange(of: focus) {
                _, focused in if focused == nil {
                    clearBuffers()
                }
            }
    }

    private var content: some View {
        #if os(iOS)
            iosContent
        #else
            VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                Text(title)
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: Spacing.small) {
                    valueText
                    Spacer(minLength: Spacing.small)
                    revealButton
                    copyButton
                }
                if let onCommit {
                    keyInput(onCommit)
                    replaceButton(onCommit)
                    if editFailed {
                        Text(UserStrings.diagnostic(.invalidKey)).font(Typography.caption)
                    }
                }
                if let footnote {
                    Text(footnote)
                        .font(Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
        #endif
    }

    #if os(iOS)
        /// The form grid: the masked value in the field column with Reveal and Copy as icon buttons at its right end (a
        /// revealed key wraps so it can be read whole), the key input as a field row, Update key and any more actions as
        /// an action row under it, and notes and the key problem as captions.
        private var iosContent: some View {
            IOSSubRows {
                IOSValueRow {
                    valueText
                } accessory: {
                    HStack(spacing: IOSDesign.Grid.buttonGap) {
                        revealButton
                        copyButton
                    }
                    .buttonStyle(.iosIcon)
                } label: {
                    Text(title)
                }
                if let onCommit {
                    IOSFieldRow(onTap: { focus = .input }) { keyInput(onCommit) } label: { Text(PlatformStrings.editorNewKey) }
                    IOSActionRow {
                        replaceButton(onCommit)
                        moreActions
                    }
                    if editFailed {
                        IOSRowCaption(UserStrings.diagnostic(.invalidKey), tone: .error)
                    }
                } else if let moreActions {
                    IOSActionRow { moreActions }
                }
                if let footnote {
                    IOSRowCaption(footnote)
                }
            }
        }
    #endif

    private var valueText: some View {
        Text(revealedText ?? SecretRevealState.mask)
        #if os(iOS)
            .font(IOSDesign.key)
        #else
            .font(Typography.code)
        #endif
            .privacySensitive()
        #if os(iOS)
            // A revealed key wraps, so all of it can be read; the mask stays on one line.
            .lineLimit(revealedText == nil ? 1 : nil)
            .fixedSize(horizontal: false, vertical: true)
        #else
            .lineLimit(1)
        #endif
            .truncationMode(.middle)
            .accessibilityLabel(Self.accessibilityLabel(title: title, phase: reveal.phase))
            .focusable()
            .focused($focus, equals: .value)
    }

    @ViewBuilder private var copyButton: some View {
        if let copier, copier.isAvailable {
            Button(MacStrings.copy, systemImage: "doc.on.doc") {
                copier.copy(loadSecret())
            }.wgexControl(.editor, "copy", label: MacStrings.copy)
        }
    }

    private func keyInput(_ onCommit: @escaping (borrowing SecretBytes) throws -> Void) -> some View {
        keyInputField.wgexControl(.editor, "keyInput", label: EditorStrings.keyInput)
            .focused($focus, equals: .input)
            .privacySensitive()
            .autocorrectionDisabled()
            .onSubmit { commit(onCommit) }
        #if os(iOS) || os(tvOS)
            .textInputAutocapitalization(.never)
        #endif
    }

    /// The key input; on iOS with a short placeholder in monospaced type, as keys are shown.
    private var keyInputField: some View {
        #if os(iOS)
            SecureField(EditorStrings.keyInput, text: $editText, prompt: iosFieldPrompt(PlatformStrings.editorKeyPlaceholder))
                .font(IOSDesign.key)
        #else
            SecureField(EditorStrings.keyInput, text: $editText)
        #endif
    }

    private func replaceButton(_ onCommit: @escaping (borrowing SecretBytes) throws -> Void) -> some View {
        Button(EditorStrings.replaceKey) { commit(onCommit) }.wgexControl(.editor, "replaceKey", label: EditorStrings.replaceKey)
            .disabled(editText.isEmpty)
            .focused($focus, equals: .commit)
    }

    private func clearBuffers() {
        revealedText = nil
        editText = ""
        reveal.hide()
    }

    private func commit(_ action: (borrowing SecretBytes) throws -> Void) {
        defer { editText = "" }
        do {
            try editText.withUTF8 { source in
                let bytes = try SecretBytes(copying: UnsafeRawBufferPointer(source))
                try action(bytes)
            }
            revealedText = nil
            reveal.hide()
            editFailed = false
        } catch { editFailed = true }
    }

    private var revealButton: some View {
        Button(
            reveal.phase == .revealed ? MacStrings.hide : MacStrings.revealOnce,
            systemImage: reveal.phase == .revealed ? "eye.slash" : "eye",
        ) {
            if reveal.phase == .revealed {
                revealedText = nil
                reveal.hide()
            } else if reveal.reveal() {
                revealedText = loadSecret()
                focus = .value
            }
        }.wgexControl(
            .editor,
            "reveal",
            label: reveal.phase == .revealed ? MacStrings.hide : MacStrings.revealOnce,
            item: WGEXAccessibility.fieldKey(title),
        )
        .disabled(reveal.phase == .spent)
    }

    private var footnote: String? {
        if let outcome = copier?.lastOutcome {
            return outcome.message
        }
        return reveal.phase == .spent ? MacStrings.revealedOnceOpenTheEditorAgain : nil
    }

    /// "Private key, hidden" and so on; the value itself is never in the label.
    public static func accessibilityLabel(title: String, phase: SecretRevealState.Phase) -> String {
        switch phase {
        case .masked: MacStrings.hidden(String(title))
        case .revealed: MacStrings.revealed(String(title))
        case .spent: MacStrings.hiddenAlreadyRevealedOnce(String(title))
        }
    }
}
