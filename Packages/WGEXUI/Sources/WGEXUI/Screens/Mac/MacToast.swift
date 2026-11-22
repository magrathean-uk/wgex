// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI

    public struct MacToast: View {
        private let message: String
        private let dismiss: () -> Void
        public init(_ message: String, dismiss: @escaping () -> Void = {}) {
            self.message = message
            self.dismiss = dismiss
        }

        public var body: some View {
            HStack(spacing: 12) {
                Text(message).font(MacDesign.body).foregroundStyle(MacDesign.text).fixedSize(horizontal: false, vertical: true)
                Button(MacStrings.dismiss, systemImage: "xmark", action: dismiss).wgexControl(.toast, "dismiss", label: MacStrings.dismiss)
                    .labelStyle(.iconOnly).buttonStyle(.plain)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(MacDesign.card, in: .rect(cornerRadius: MacDesign.Radius.card))
            .overlay {
                RoundedRectangle(cornerRadius: MacDesign.Radius.card).strokeBorder(MacDesign.cardBorder, lineWidth: MacDesign.Stroke.card)
            }
            .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
            .accessibilityIdentifier("wgex.toast.message")
            .accessibilityElement(children: .contain)
            .accessibilityLabel(message)
        }
    }
#endif
