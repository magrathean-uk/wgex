// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import UIKit
    import WGEXCore

    private struct IOSArchiveShareSheet: UIViewControllerRepresentable {
        let url: URL

        func makeUIViewController(context _: Context) -> UIActivityViewController {
            UIActivityViewController(activityItems: [url], applicationActivities: nil)
        }

        func updateUIViewController(_: UIActivityViewController, context _: Context) {}
    }

    /// General (SPEC 8.1 where iOS has the setting): the zip export of every tunnel and the note that closing the app
    /// leaves the tunnel up. Default tunnel, start-up, Dock and notification settings do not exist on iOS.
    public struct IOSGeneralPage<Model: IOSAppState>: View {
        private let model: Model
        @State private var exporting = false
        @State private var sharing = false
        @State private var exportURL: URL?
        @State private var exportFailed = false

        public init(model: Model) {
            self.model = model
        }

        public var body: some View {
            Form {
                Section {
                    Button(PlatformStrings.exportZipArchive) {
                        exporting = true
                        exportFailed = false
                        Task {
                            defer { exporting = false }
                            do {
                                exportURL = try await model.exportArchive()
                                sharing = true
                            } catch { exportFailed = true }
                        }
                    }
                    .disabled(exportDisabled)
                    .opacity(exportDisabled ? 0.45 : 1)
                    .accessibilityIdentifier("wgex.general.exportArchive")
                    if exportFailed {
                        Text(PlatformStrings.archiveCouldNotBeExported).foregroundStyle(IOSDesign.textSecondary)
                    }
                } footer: {
                    Text(PlatformStrings.exportZipArchiveNote)
                }
                Section {} footer: {
                    Text(PlatformStrings.closingDoesNotDeactivateTheTunnel)
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.general)
            .sheet(isPresented: $sharing, onDismiss: removeArchive) {
                if let exportURL {
                    IOSArchiveShareSheet(url: exportURL)
                }
            }
        }

        private var exportDisabled: Bool {
            model.profiles.isEmpty || model.isBusy || exporting
        }

        private func removeArchive() {
            if let exportURL {
                try? FileManager.default.removeItem(at: exportURL.deletingLastPathComponent())
            }
            exportURL = nil
        }
    }

    /// Protection (SPEC 8.2 where iOS has the setting): Force all traffic, Allow local network and DNS, each a control on
    /// this page only, then what WGEX cannot protect. iOS has no kill switch, Lockdown or sign-in window setting.
    public struct IOSProtectionPage<Model: IOSAppState>: View {
        private let model: Model
        @State private var warning = false
        @FocusState private var domainsFocused: Bool
        @Namespace private var transitions

        public init(model: Model) {
            self.model = model
        }

        public var body: some View {
            Form {
                Section {
                    Toggle(PlatformStrings.forceAllTraffic, isOn: Binding(get: { model.protection.ios.includeAllNetworks }, set: {
                        if $0 {
                            warning = true
                        } else {
                            model.protection.ios.includeAllNetworks = false
                        }
                    }))
                    .matchedTransitionSource(id: "force", in: transitions)
                    .accessibilityIdentifier("wgex.protection.forceAllTraffic")
                } footer: {
                    Text(PlatformStrings.forceAllTrafficNote)
                }
                Section {
                    Toggle(MacStrings.allowLocalNetwork, isOn: Binding(get: { model.protection.ios.excludeLocalNetworks }, set: {
                        model.protection.ios.excludeLocalNetworks = $0
                    }))
                    .accessibilityIdentifier("wgex.protection.allowLocalNetwork")
                } footer: {
                    Text(MacStrings.allowLocalNetworkNote)
                }
                Section {
                    dnsRow
                    if case let .split(domains) = model.protection.dnsPolicy {
                        TextField(EditorStrings.splitDomains, text: Binding(get: { domains.joined(separator: ", ") }, set: {
                            model.protection.dnsPolicy = .split(
                                $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty },
                            )
                        }))
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                        .focused($domainsFocused)
                        // The whole 44 pt row focuses the field, not only its line of text.
                        .frame(maxWidth: .infinity, minHeight: domainsRowHeight, alignment: .leading)
                        .iosRowTapArea { domainsFocused = true }
                    }
                } footer: {
                    if model.protection.dnsPolicy == .systemDefault {
                        Text(UserStrings.systemDNSWarning)
                    }
                }
                Section(MacStrings.whatWGEXCannotProtect) {
                    Text(MacStrings.limitLocalNetwork).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                    Text(PlatformStrings.limitRouteExclusions).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.protection)
            .onDisappear { Task { await model.savePreferences() } }
            .sheet(isPresented: $warning) {
                WarningSheet(content: .forceAllTraffic, onConfirm: {
                    model.protection.ios.includeAllNetworks = true; warning = false
                }, onCancel: { warning = false })
                    .modifier(ShellZoomTransition(id: "force", namespace: transitions))
            }
        }

        /// The DNS pop-up as a value row: the label on the left, the chosen policy on the right in textSecondary with an
        /// up-down glyph, and the whole row opens the menu of choices.
        private var dnsRow: some View {
            Menu {
                Picker(PlatformStrings.dnsPolicy, selection: Binding(
                    get: { model.protection.dnsPolicy },
                    set: { model.protection.dnsPolicy = $0 },
                )) {
                    Text(EditorStrings.tunnelDNS).tag(DNSPolicy.tunnelAll)
                    Text(EditorStrings.splitDNS).tag(splitPolicy)
                    Text(EditorStrings.systemDNS).tag(DNSPolicy.systemDefault)
                }
            } label: {
                LabeledContent(PlatformStrings.dnsPolicy) {
                    HStack(spacing: IOSDesign.Space.micro * 2) {
                        Text(dnsPolicyName)
                        Image(systemName: "chevron.up.chevron.down")
                            .font(IOSDesign.footer.weight(.semibold))
                            .foregroundStyle(IOSDesign.label3)
                            .accessibilityHidden(true)
                    }
                }
            }
            .menuStyle(.button)
            .buttonStyle(.iosRowAction)
            .accessibilityLabel(Text(PlatformStrings.dnsPolicy))
            .accessibilityValue(Text(dnsPolicyName))
        }

        /// The split-domains field's height inside its card row's padding, so the field fills the 44 pt row.
        private var domainsRowHeight: CGFloat {
            IOSDesignScale.minimumTouchHeight - 2 * IOSDesign.Space.rowVertical
        }

        private var dnsPolicyName: String {
            switch model.protection.dnsPolicy {
            case .tunnelAll: EditorStrings.tunnelDNS
            case .split: EditorStrings.splitDNS
            case .systemDefault: EditorStrings.systemDNS
            }
        }

        private var splitPolicy: DNSPolicy {
            if case .split = model.protection.dnsPolicy {
                model.protection.dnsPolicy
            } else {
                .split([])
            }
        }
    }

    /// About (SPEC 8.5, DEC-110 items 19 and 20): name, version with build, MIT licence, thanks to WireGuard, the
    /// bundled WireGuard revision and the licences. No documentation row.
    public struct IOSAboutPage: View {
        private let engineVersion: String

        public init(engineVersion: String) {
            self.engineVersion = engineVersion
        }

        public var body: some View {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                        Text(MacStrings.appName).font(.title2.bold())
                        Text(AboutText.versionLine(Bundle.main.infoDictionary))
                            .foregroundStyle(IOSDesign.textSecondary).monospacedDigit().textSelection(.enabled)
                        Text(MacStrings.mitLicence).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("wgex.about.identity")
                    LabeledContent(PlatformStrings.wireGuardBackend, value: engineVersion).textSelection(.enabled)
                }
                Section(MacStrings.acknowledgements) {
                    Text(MacStrings.thanksToWireGuard)
                    LabeledContent("wireguard-apple", value: MacStrings.wireGuardLicence)
                    LabeledContent("wombat-vpn", value: MacStrings.wombatLicence)
                    LabeledContent(MacStrings.firezoneSwiftComponents, value: MacStrings.firezoneLicence)
                    Text(MacStrings.thirdPartyLicenceNoticesAre).font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                }
                Section {} footer: {
                    Text(MacStrings.wireGuardTrademarkDisclaimer)
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.about)
        }
    }
#endif
