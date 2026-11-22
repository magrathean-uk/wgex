// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import WGEXCore

    public struct IOSOnboardingScreen<Model: IOSAppState>: View {
        private let model: Model
        @State private var step = 1
        @State private var importing = false
        @State private var warning = false
        @State private var editing = false

        public init(model: Model) {
            self.model = model
        }

        public var body: some View {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: IOSDesign.Space.detail) {
                        stepIndicator
                        Image(systemName: "network.badge.shield.half.filled")
                            .font(.system(size: IOSDesign.TypeSize.welcome))
                            .foregroundStyle(IOSDesign.accent)
                            .frame(width: 64, height: 64)
                            .background(IOSDesign.card, in: .rect(cornerRadius: IOSDesign.Radius.card))
                            .overlay {
                                RoundedRectangle(cornerRadius: IOSDesign.Radius.card)
                                    .strokeBorder(IOSDesign.cardBorder, lineWidth: IOSDesign.Stroke.card)
                            }
                        Text(title).font(.system(size: IOSDesign.TypeSize.welcome, weight: .bold))
                            .foregroundStyle(IOSDesign.text)
                            .accessibilityAddTraits(.isHeader)
                        Text(message).font(IOSDesign.body).foregroundStyle(IOSDesign.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                        IOSCardRows { accessory }
                            .font(IOSDesign.body).foregroundStyle(IOSDesign.text)
                            .labeledContentStyle(IOSRowLabeledContentStyle())
                        actions
                    }
                    .padding(IOSDesign.Space.page)
                    .frame(maxWidth: 470, alignment: .leading)
                    .frame(maxWidth: .infinity)
                }
                .background(IOSDesign.pageBackground)
                .tint(IOSDesign.accent)
                .navigationTitle("Welcome to WGEX")
                .sheet(isPresented: $importing, onDismiss: {
                    if model.editor == nil {
                        model.cancelImport()
                    } else {
                        editing = true
                    }
                }) {
                    IOSAddTunnelSheet(model: model, initialSource: .review, createEmpty: {
                        model.cancelImport()
                        model.createFromScratch()
                        importing = false
                    }) { importing = false }
                }
                .iosEditorSheet(model: model, isPresented: $editing)
                .sheet(isPresented: $warning) {
                    WarningSheet(content: .forceAllTraffic, onConfirm: {
                        model.protection.ios.includeAllNetworks = true; warning = false
                    }, onCancel: { warning = false })
                }
            }
            .interactiveDismissDisabled()
        }

        private var stepIndicator: some View {
            HStack(spacing: IOSDesign.Space.small) {
                ForEach(1 ... 5, id: \.self) { index in
                    RoundedRectangle(cornerRadius: 2).fill(index == step ? IOSDesign.accent : IOSDesign.hairline)
                        .frame(width: index == step ? 24 : 8, height: 8)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(OnboardingCopy.stepLabel(index: step, count: 5))
        }

        private var actions: some View {
            VStack(spacing: IOSDesign.Space.medium) {
                Button(step == 5 ? "Finish setup" : "Continue", action: advance)
                    .buttonStyle(.iosPrimary)
                if step > 1 {
                    Button("Back") { step -= 1 }.buttonStyle(.iosSecondary)
                }
            }.frame(maxWidth: .infinity)
        }

        @ViewBuilder private var accessory: some View {
            switch step {
            case 2:
                Button(MacStrings.addTunnel) { importing = true }.buttonStyle(.iosSecondary)
                    .accessibilityIdentifier("wgex.onboarding.addTunnel")
                Text(model.profiles.isEmpty ? "No tunnels yet. You can add one later." : "Your tunnel is ready.")
            case 3:
                #if DEBUG
                    Label(model.backendMessage, systemImage: "info.circle")
                #else
                    Label("Your tunnel uses the iOS VPN configuration.", systemImage: "info.circle")
                #endif
            case 4:
                Label("Set on-demand rules with Edit on the tunnel's page.", systemImage: "antenna.radiowaves.left.and.right")
            case 5:
                LabeledContent("Force all traffic", value: model.protection.ios.includeAllNetworks ? "On" : "Off")
                Button("Read the warning") { warning = true }.buttonStyle(.iosSecondary)
            default:
                Label("No accounts. No provided servers. No analytics.", systemImage: "hand.raised")
            }
        }

        private var title: String {
            switch step {
            case 1: "Your connection. Your server."
            case 2: "Add your first tunnel"
            case 3: "Allow a VPN connection"
            case 4: "Connect on demand"
            default: "Force all traffic is optional"
            }
        }

        private var message: String {
            switch step {
            case 1: "Import a configuration for your own WireGuard server. Your configuration stays on your device. Only your chosen VPN server receives tunnel traffic. WGEX does not collect analytics."
            case 2: "Scan QR, choose Files, paste a configuration or import a ZIP."
            case 3: "Before the first connection, iOS will ask to add a VPN configuration. This lets WGEX route traffic through your server. You can manage it in system Settings. This explanation comes before that permission."
            case 4: "Each tunnel can connect on its own on cellular, on Wi-Fi, or on chosen Wi-Fi networks. Set this in the tunnel's editor. A hostile network can imitate a listed Wi-Fi name."
            default: "Force all traffic starts off. It changes routing for system services and can interrupt connectivity during updates, CarPlay, Personal Hotspot and local DNS. Read the warning before enabling it."
            }
        }

        private func advance() {
            if step < 5 {
                step += 1
            } else {
                model.onboardingComplete = true
                Task { await model.savePreferences() }
            }
        }
    }
#endif
