// SPDX-License-Identifier: MIT

import SwiftUI
import WGEXCore

/// A text field for one IPv4 or IPv6 prefix, with inline validation.
public struct CIDRField: View {
    @Binding private var text: String
    private let title: String
    private let row: ValidatedFieldRow

    /// Creates a field.
    public init(_ title: String = MacStrings.address, text: Binding<String>) {
        self.title = title
        _text = text
        row = ValidatedFieldRow()
    }

    /// A field whose visible row label (empty for a row that continues the one above) and in-box accessory differ from
    /// its title, which stays its accessibility label and identifier.
    fileprivate init(_ title: String, text: Binding<String>, row: ValidatedFieldRow) {
        self.title = title
        _text = text
        self.row = row
    }

    /// The view body.
    public var body: some View {
        let validation = AllowedIPsModel.validate(text)
        ValidatedField(
            title: title,
            prompt: "10.0.0.2/32",
            text: $text,
            validation: validation,
            accessibilityLabel: Self.accessibilityLabel(title: title, validation: validation),
            row: row,
        )
    }

    /// "Address, valid".
    public static func accessibilityLabel(title: String, validation: FieldValidation) -> String {
        MacStrings.fieldValidation(String(title), String(validation.spoken))
    }
}

/// A text field for `host:port`, with inline validation.
public struct EndpointField: View {
    @Binding private var text: String
    private let title: String
    private let validationOverride: FieldValidation?

    /// Creates a field.
    public init(_ title: String = MacStrings.endpoint, text: Binding<String>, validation: FieldValidation? = nil) {
        validationOverride = validation
        self.title = title
        _text = text
    }

    /// The view body.
    public var body: some View {
        let validation = validationOverride ?? Self.validate(text)
        ValidatedField(
            title: title,
            prompt: "vpn.example.com:51820",
            text: $text,
            validation: validation,
            accessibilityLabel: CIDRField.accessibilityLabel(title: title, validation: validation),
            row: ValidatedFieldRow(),
        )
    }

    /// Validates endpoint text.
    public static func validate(_ text: String) -> FieldValidation {
        switch EndpointText.parse(text) {
        case .success: .valid
        case .failure(.empty): .empty
        case let .failure(error): .invalid(error.message)
        }
    }
}

/// How an iOS grid row shows a validated field: the visible label (the title when nil, nothing when empty) and a view at
/// the right end of the field box. Other platforms ignore it.
private struct ValidatedFieldRow {
    var label: String?
    var accessory: AnyView?
}

/// Shared layout: monospaced field and a message line when invalid.
private struct ValidatedField: View {
    let title: String
    let prompt: String
    @Binding var text: String
    let validation: FieldValidation
    let accessibilityLabel: String
    let row: ValidatedFieldRow

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
            #if os(iOS)
                IOSFieldRow { field } accessory: { row.accessory } label: {
                    if let label = row.label ?? Optional(title), !label.isEmpty {
                        Text(label)
                    }
                }
                if let message = validation.message {
                    IOSRowCaption(message, tone: .error).accessibilityHidden(true)
                }
            #else
                field
                if let message = validation.message {
                    Label(message, systemImage: "exclamationmark.circle")
                        .font(Typography.caption)
                        .foregroundStyle(StateColor.unprotected.color)
                        .accessibilityHidden(true)
                }
            #endif
        }
    }

    private var field: some View {
        TextField(title, text: $text, prompt: promptText).wgexControl(
            .editor,
            "validatedField",
            label: title,
            item: WGEXAccessibility.fieldKey(title),
        )
        #if os(iOS)
        .font(IOSDesign.key)
        #else
        .font(Typography.code)
        #endif
        .autocorrectionDisabled()
        .accessibilityLabel(accessibilityLabel)
        #if os(iOS) || os(tvOS)
            .textInputAutocapitalization(.never)
        #endif
        #if os(iOS)
        .keyboardType(.numbersAndPunctuation)
        #endif
    }

    private var promptText: Text {
        #if os(iOS)
            iosFieldPrompt(prompt)
        #else
            Text(prompt)
        #endif
    }
}

/// Editor for a peer's AllowedIPs with "All traffic" and "Exclude private
/// networks" helpers.
public struct AllowedIPsEditor: View {
    @Binding private var model: AllowedIPsModel
    private let dnsServers: [String]

    /// Creates an editor. `dnsServers` are the profile's DNS servers: the "Exclude private
    /// networks" control keeps each one routed through the tunnel and ignores their host routes.
    public init(model: Binding<AllowedIPsModel>, dnsServers: [String] = []) {
        _model = model
        self.dnsServers = dnsServers
    }

    /// The view body.
    public var body: some View {
        content
            .accessibilityElement(children: .contain)
            .accessibilityLabel(Self.accessibilityLabel(for: model, dnsServers: dnsServers))
    }

    #if os(iOS)
        /// The form grid: "Allowed IPs" labels the first address; each address is a full-width field with its remove glyph
        /// at the box's right end; All traffic and Add as an action row under them; Exclude private networks as a switch
        /// row; the summary as a caption.
        private var content: some View {
            IOSSubRows {
                ForEach($model.entries) { $entry in
                    let first = entry.id == model.entries.first?.id
                    CIDRField(MacStrings.allowedIP, text: $entry.text, row: ValidatedFieldRow(
                        label: first ? MacStrings.allowedIPs : "", accessory: AnyView(removeButton(entry.id)),
                    ))
                    .iosRowKind(first ? .row : .continuation)
                }
                if model.entries.isEmpty {
                    IOSActionRow { allTrafficButton; addButton } label: { Text(MacStrings.allowedIPs) }
                } else {
                    IOSActionRow { allTrafficButton; addButton }
                }
                excludeToggle
                IOSRowCaption(model.summaryText(dnsServers: dnsServers))
            }
        }

        /// The remove glyph inside an address box: a 20 pt square in the error colour, its hit area a 44 pt touch target.
        private func removeButton(_ id: AllowedIPsModel.Entry.ID) -> some View {
            Button(MacStrings.remove, systemImage: "minus.circle") {
                model.remove(id: id)
            }.wgexControl(.editor, "remove", label: MacStrings.remove)
                .buttonStyle(.iosGlyph).foregroundStyle(IOSDesign.error)
        }
    #else
        private var content: some View {
            VStack(alignment: .leading, spacing: Spacing.medium) {
                Text(MacStrings.allowedIPs)
                    .font(Typography.cardTitle)
                ForEach($model.entries) { $entry in
                    HStack(alignment: .firstTextBaseline, spacing: Spacing.small) {
                        CIDRField(MacStrings.allowedIP, text: $entry.text)
                        Button(MacStrings.remove, systemImage: "minus.circle") {
                            model.remove(id: entry.id)
                        }.wgexControl(.editor, "remove", label: MacStrings.remove)
                            .labelStyle(.iconOnly)
                    }
                }
                HStack(spacing: Spacing.small) {
                    allTrafficButton
                    excludeToggle
                    addButton
                }
                .buttonStyle(.glass)
                Text(model.summaryText(dnsServers: dnsServers))
                    .font(Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    #endif

    private var allTrafficButton: some View {
        Button(MacStrings.allTraffic) { model.setAllTraffic() }.wgexControl(.editor, "allTraffic", label: MacStrings.allTraffic)
    }

    private var excludeToggle: some View {
        Toggle(MacStrings.excludePrivateNetworks, isOn: excludesPrivateNetworks)
            .disabled(model.privateNetworkExclusion(dnsServers: dnsServers) == .unavailable)
            .wgexControl(.editor, "excludePrivateNetworks", label: MacStrings.excludePrivateNetworks)
    }

    /// "+ Add"; on iOS the plus and the word one step apart, as a compact button's label.
    private var addButton: some View {
        Button(MacStrings.add, systemImage: "plus") { model.add() }.wgexControl(.editor, "add", label: MacStrings.add)
        #if os(iOS)
            .labelStyle(.iosCompact)
        #endif
    }

    /// The control's state; unavailable reads as off and the toggle is disabled.
    private var excludesPrivateNetworks: Binding<Bool> {
        Binding(
            get: { model.privateNetworkExclusion(dnsServers: dnsServers) == .on },
            set: { model.setPrivateNetworksExcluded($0, dnsServers: dnsServers) },
        )
    }

    /// "Allowed IPs, All traffic, valid".
    public static func accessibilityLabel(for model: AllowedIPsModel, dnsServers: [String] = []) -> String {
        MacStrings.allowedIPsAnnouncement(
            String(model.summaryText(dnsServers: dnsServers)),
            String(model.isValid ? "valid" : "needs fixing"),
        )
    }
}
