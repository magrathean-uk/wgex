// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore
import WGEXUI

/// Form components: secret field with the fake pasteboard, address and
/// endpoint fields (valid and invalid), the AllowedIPs editor and the
/// warning sheet.
public struct FormComponentsGallery: View {
    @State private var address = "10.0.0.2/32"
    @State private var badAddress = "10.0.0.0/33"
    @State private var endpoint = "vpn.example.com:51820"
    @State private var badEndpoint = "vpn.example.com"
    @State private var allowedIPs = AllowedIPsModel(["0.0.0.0/0", "::/0"])
    @State private var copier = SecretCopyController(policy: .current, pasteboard: FakeSecretPasteboard())

    /// Creates the gallery.
    public init() {}

    /// The view body.
    public var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            SecretField("Private key", copier: copier) { "preview-placeholder-not-a-key" }
            CIDRField(text: $address)
            CIDRField(text: $badAddress)
            EndpointField(text: $endpoint)
            EndpointField(text: $badEndpoint)
            AllowedIPsEditor(model: $allowedIPs)
            WarningSheet(content: .forceAllTraffic, onConfirm: {}, onCancel: {})
                .frame(height: 420)
        }
    }
}

#Preview("Form components, light") {
    ScrollView { FormComponentsGallery().previewTraits(.light) }
}

#Preview("Form components, dark") {
    ScrollView { FormComponentsGallery().previewTraits(.dark) }
}

#Preview("Form components, every variant") {
    PreviewTraitsMatrix { FormComponentsGallery() }
}

#Preview("Warning sheet, Force all traffic") {
    WarningSheet(content: .forceAllTraffic, onConfirm: {}, onCancel: {})
        .previewTraits(.light)
}
