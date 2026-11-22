// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore

/// The review's title and button words; the defaults are the shared words, and iPhone and iPad pass the Mac's.
public struct ImportReviewLabels: Sendable {
    public var title: String
    public var add: String
    public var addAndActivate: String

    public init(title: String, add: String, addAndActivate: String) {
        self.title = title; self.add = add; self.addAndActivate = addAndActivate
    }

    public static let standard = ImportReviewLabels(
        title: EditorStrings.review, add: EditorStrings.importProfile, addAndActivate: EditorStrings.importConnect,
    )
}

public struct ImportReviewScreen: View {
    @Bindable private var model: ImportReviewModel
    private let labels: ImportReviewLabels
    private let onImport: (TunnelProfile, borrowing ParsedSecrets) throws -> Void
    private let onImportAndConnect: (TunnelProfile, borrowing ParsedSecrets) throws -> Void

    public init(
        model: ImportReviewModel,
        onImport: @escaping (TunnelProfile, borrowing ParsedSecrets) throws -> Void,
        onImportAndConnect: @escaping (TunnelProfile, borrowing ParsedSecrets) throws -> Void,
        labels: ImportReviewLabels = .standard,
    ) {
        self.model = model; self.onImport = onImport; self.onImportAndConnect = onImportAndConnect; self.labels = labels
    }

    public var body: some View {
        Form {
            Section(EditorStrings.interface) { TextField(EditorStrings.name, text: $model.name).wgexControl(
                .importReview,
                "name",
                label: EditorStrings.name,
            ) }
            if model.showsIPv6PolicyChoice {
                Section(EditorStrings.ipv6) { ImportIPv6PolicyPicker(model: model) }
            }
            if !model.errors.isEmpty {
                Section(EditorStrings.errors) { EditorDiagnosticsView(model.errors); Text(EditorStrings.importBlocked) }
            }
            if !model.warnings.isEmpty {
                Section(EditorStrings.warnings) {
                    EditorDiagnosticsView(model.warnings)
                    if model.warnings.contains(where: { $0.code == .ignoredHook }) {
                        Text(EditorStrings.hookWarning)
                    }
                }
            }
            if !model.duplicates.isEmpty {
                Section(EditorStrings.duplicates) {
                    if model.duplicates.contains(where: \.sameName) {
                        Text(EditorStrings.duplicateName)
                    }
                    if model.keyInUseElsewhere {
                        Text(EditorStrings.duplicateKey)
                    }
                }
            }
            Section {
                Button(labels.add) { model.confirm(using: onImport) }.wgexControl(
                    .importReview,
                    "importProfile",
                    label: labels.add,
                )
                .importReviewButton(prominent: false).disabled(!model.canImport)
                Button(labels.addAndActivate) { model.confirm(using: onImportAndConnect) }.wgexControl(
                    .importReview,
                    "importConnect",
                    label: labels.addAndActivate,
                )
                .importReviewButton(prominent: true).disabled(!model.canImport)
                if model.actionFailed {
                    Text(EditorStrings.importFailed)
                }
            }
        }
        .navigationTitle(labels.title)
    }
}

private extension View {
    /// Add and Add and Activate: the sheet's secondary and primary buttons on iPhone and iPad (layout C), glass elsewhere.
    @ViewBuilder func importReviewButton(prominent: Bool) -> some View {
        #if os(iOS)
            if prominent {
                buttonStyle(.iosPrimary)
            } else {
                buttonStyle(.iosSecondary)
            }
        #else
            if prominent {
                buttonStyle(.glassProminent)
            } else {
                buttonStyle(.glass)
            }
        #endif
    }
}

/// Shared import choice; tunnel routing is unavailable when the interface has no IPv6 address.
package struct ImportIPv6PolicyPicker: View {
    @Bindable package var model: ImportReviewModel

    package var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker(EditorStrings.ipv6, selection: $model.ipv6Policy) {
                Text(EditorStrings.blockIPv6).tag(IPv6Policy.blockOutside)
                Text(EditorStrings.allowIPv6).tag(IPv6Policy.allowOutside)
            }.wgexControl(.importReview, "ipv6", label: EditorStrings.ipv6)
            if model.ipv6Policy == .allowOutside {
                Text(MacStrings.ipv6OutsideTunnelConsequence).font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
