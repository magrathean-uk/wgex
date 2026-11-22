// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import SwiftUI

    /// About (SPEC 8.5): name, version with build, licence, acknowledgements and the WireGuard trademark line.
    package struct MacAboutPage: View {
        private let acknowledgements: String

        package init(acknowledgements: String) {
            self.acknowledgements = acknowledgements
        }

        package var body: some View {
            Form {
                Section {
                    HStack(spacing: 16) {
                        Image(nsImage: NSImage(named: "WGEXArtwork") ?? NSApplication.shared.applicationIconImage)
                            .resizable().frame(width: 64, height: 64)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(MacStrings.appName).font(MacDesign.pageTitle).lineLimit(1)
                            Text(MacAppPagesPresentation.versionLine(Bundle.main.infoDictionary))
                                .font(MacDesign.small).foregroundStyle(MacDesign.label2).lineLimit(1).fixedSize()
                                .textSelection(.enabled)
                            Text(MacStrings.mitLicence).font(MacDesign.small).foregroundStyle(MacDesign.label2).lineLimit(1)
                        }
                    }
                    .padding(.vertical, 6)
                }
                if let documentation = MacAppPagesPresentation.documentationURL(Bundle.main.infoDictionary) {
                    Section {
                        Link(destination: documentation) {
                            Text(MacStrings.documentationLink).lineLimit(1)
                        }
                        .foregroundStyle(MacDesign.accent)
                        .wgexControl(.settings, "documentation", label: MacStrings.documentationLink)
                        .help(documentation.absoluteString)
                    }
                }
                Section(MacStrings.acknowledgements) {
                    Text(MacStrings.thanksToWireGuard)
                    Text(acknowledgements).textSelection(.enabled)
                }
                Section {
                    Text(MacStrings.wireGuardTrademarkDisclaimer).font(MacDesign.caption).foregroundStyle(MacDesign.label2)
                }
            }
            .formStyle(.macCards(title: MacSettingsTab.about.title))
        }
    }
#endif
