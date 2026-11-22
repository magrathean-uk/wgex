// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI

    /// The Add a Tunnel content (SPEC 6.1): three grouped rows, no QR import (D8). The sidebar's Add Tunnel… hosts it with
    /// Cancel; first-run setup hosts the same view with its own dismiss title ("Not Now") and action.
    public struct MacAddTunnelView: View {
        private let chooseFile: () -> Void
        private let paste: () -> Void
        private let createEmpty: () -> Void
        private let dismissTitle: String
        private let dismiss: (() -> Void)?
        private let showsHeading: Bool
        private let message: String?

        /// `dismiss` nil leaves out the button row; `message` is the one-line outcome of the last action (an empty clipboard).
        public init(
            chooseFile: @escaping () -> Void = {},
            paste: @escaping () -> Void = {},
            createEmpty: @escaping () -> Void = {},
            dismissTitle: String = MacStrings.cancel,
            dismiss: (() -> Void)? = nil,
            showsHeading: Bool = true,
            message: String? = nil,
        ) {
            self.chooseFile = chooseFile; self.paste = paste; self.createEmpty = createEmpty
            self.dismissTitle = dismissTitle; self.dismiss = dismiss; self.showsHeading = showsHeading; self.message = message
        }

        public var body: some View {
            VStack(alignment: .leading, spacing: MacDesign.Space.groupGap) {
                if showsHeading {
                    Text(MacStrings.addATunnelTitle).font(MacDesign.heading).foregroundStyle(MacDesign.text).lineLimit(1)
                }
                Text(MacStrings.addATunnelMessage).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(spacing: 0) {
                    row(MacStrings.importFromFile, action: chooseFile).wgexControl(
                        .importReview,
                        "chooseFile",
                        label: MacStrings.importFromFile,
                    )
                    hairline
                    row(MacStrings.pasteFromClipboard, action: paste).wgexControl(
                        .importReview,
                        "paste",
                        label: MacStrings.pasteFromClipboard,
                    )
                    hairline
                    row(MacStrings.createEmptyTunnel, action: createEmpty)
                        .wgexControl(.importReview, "createEmpty", label: MacStrings.createEmptyTunnel)
                }
                .macCard(padding: 0)
                if let message {
                    Text(message).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        .fixedSize(horizontal: false, vertical: true)
                        .wgexAX(.importReview, "errorMessage", label: message)
                }
                if let dismiss {
                    HStack {
                        Spacer()
                        Button(dismissTitle, action: dismiss).wgexControl(.importReview, "cancel", label: dismissTitle)
                            .keyboardShortcut(.cancelAction).lineLimit(1)
                    }
                }
            }
        }

        private var hairline: some View {
            Rectangle().fill(MacDesign.hairline).frame(height: 0.5).padding(.leading, MacDesign.Space.rowHorizontal)
        }

        private func row(_ title: String, action: @escaping () -> Void) -> some View {
            Button(action: action) {
                HStack {
                    Text(title).font(MacDesign.body.weight(.medium)).foregroundStyle(MacDesign.accent).lineLimit(1)
                    Spacer(minLength: 12)
                }
                .padding(.horizontal, MacDesign.Space.rowHorizontal).padding(.vertical, 7)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
        }
    }
#endif
