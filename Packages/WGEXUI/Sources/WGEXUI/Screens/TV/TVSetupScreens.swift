// SPDX-License-Identifier: MIT

#if os(tvOS)
    import SwiftUI
    import WGEXCore

    public struct TVFirstRunScreen: View {
        @Binding private var settings: TVSettings
        private let onContinue: () -> Void
        public init(settings: Binding<TVSettings>, onContinue: @escaping () -> Void) {
            _settings = settings; self.onContinue = onContinue
        }

        public var body: some View {
            OnboardingStep(
                title: "Your connection. Your server.",
                message: "Import a configuration for your own WireGuard server. No accounts. No provided servers. No analytics. What leaves this device: your WireGuard traffic and local pairing messages.",
                index: 1,
                count: 2,
                primary: OnboardingAction("Continue") {
                    settings.privacyAccepted = true; onContinue()
                },
            ) {
                Toggle("Keep connected (always-on)", isOn: $settings.alwaysOn)
                Text("Apple TV cannot enforce a kill switch").font(.footnote)
            }
            .padding(60).focusSection().accessibilityIdentifier("tv.firstRun")
        }
    }

    public struct TVEmptyProfilesScreen: View {
        private let onPair: () -> Void
        private let onPaste: () -> Void
        public init(onPair: @escaping () -> Void, onPaste: @escaping () -> Void) {
            self.onPair = onPair; self.onPaste = onPaste
        }

        public var body: some View {
            OnboardingStep(
                title: "Add your first profile",
                message: "Use a configuration made for this Apple TV.",
                index: 2,
                count: 2,
                primary: OnboardingAction("Add from iPhone or Mac", perform: onPair),
                secondary: OnboardingAction("Paste a configuration", perform: onPaste),
            )
            .padding(60).focusSection().accessibilityIdentifier("tv.empty")
        }
    }

    public struct TVSettingsScreen: View {
        @Binding private var settings: TVSettings
        @Binding private var flags: FeatureFlags
        public init(settings: Binding<TVSettings>, flags: Binding<FeatureFlags>) {
            _settings = settings; _flags = flags
        }

        public var body: some View {
            Form {
                Section("Connection") {
                    Toggle("Keep connected (always-on)", isOn: $settings.alwaysOn)
                    Text("Reconnect automatically on any network. Disconnecting manually pauses always-on until you connect again.")
                    Toggle("Allow LAN", isOn: $settings.allowLAN)
                    Text(
                        "Route enforcement is enabled. Allow LAN excludes local network routes so local devices can be reached outside the tunnel.",
                    )
                    Text("Apple TV cannot enforce a kill switch").font(.footnote)
                }.focusSection()
                Section("DNS policy") {
                    Picker("DNS policy", selection: $settings.dnsPolicy) {
                        Text("All DNS through the tunnel").tag(DNSPolicy.tunnelAll)
                        Text("System default").tag(DNSPolicy.systemDefault)
                        if case .split = settings.dnsPolicy {
                            Text("Split DNS (from profile)").tag(settings.dnsPolicy)
                        }
                    }
                    if settings.dnsPolicy == .systemDefault {
                        Text("DNS queries can leave outside the tunnel.")
                    }
                }.focusSection()
                Section("Display") { Toggle("Events on screen", isOn: $settings.eventsOnScreen) }.focusSection()
                TransportSettingsSection(flags: $flags).focusSection()
                if flags.relayTransports {
                    Section("Transports") { Text("Direct WireGuard"); Text("No relay is configured yet.") }.focusSection()
                }
                AboutSettingsSection().focusSection()
            }.navigationTitle("Settings")
        }
    }

    public struct TVPasteImportScreen: View {
        @Bindable private var model: TVPasteImportModel
        private let existing: [TunnelProfile]
        private let onImport: (TunnelProfile, borrowing ParsedSecrets, Bool) throws -> Void
        public init(
            model: TVPasteImportModel,
            existing: [TunnelProfile] = [],
            onImport: @escaping (TunnelProfile, borrowing ParsedSecrets, Bool) throws -> Void,
        ) {
            self.model = model; self.existing = existing; self.onImport = onImport
        }

        public var body: some View {
            Group {
                if let review = model.review {
                    VStack {
                        if !review.profile.interface.addresses.contains(where: \.isIPv6) {
                            Text("IPv6 outside the tunnel will be blocked for this IPv4-only configuration.").font(.footnote)
                        }
                        ImportReviewScreen(
                            model: review,
                            onImport: { try onImport($0, $1, false) },
                            onImportAndConnect: { try onImport($0, $1, true) },
                        ).focusSection()
                    }
                } else {
                    VStack(alignment: .leading, spacing: 32) {
                        Text("Paste a configuration").font(.largeTitle.bold())
                        Text("Use the keyboard on your iPhone to paste a configuration.")
                        TextField("WireGuard configuration", text: $model.text)
                            .frame(minHeight: 240).padding(20)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .privacySensitive().accessibilityLabel("Whole WireGuard configuration")
                        Button("Review import") { model.prepare(existing: existing) }
                            .disabled(model.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                            .accessibilityIdentifier("tv.reviewImport")
                    }.padding(60).focusSection()
                }
            }.navigationTitle("Paste a configuration").onDisappear { model.clear() }
        }
    }
#endif
