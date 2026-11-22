// SPDX-License-Identifier: MIT

#if os(tvOS)
    import SwiftUI
    import WGEXCore
    import WGEXUI

    private struct TVScreenPreview: View {
        enum Screen { case connection, profiles, firstRun, empty, settings, pairing, sas, expired, overwrite, completed, paste, review }
        let screen: Screen
        @State private var settings = TVSettings()
        @State private var flags = FeatureFlags.defaults
        @State private var paste = TVPasteImportModel()
        private var pairingStage: TVPairingSnapshot.Stage {
            switch screen {
            case .sas: .confirmSAS
            case .expired: .expired
            case .overwrite: .overwrite
            case .completed: .completed
            default: .waiting
            }
        }

        var body: some View {
            NavigationStack {
                switch screen {
                case .connection:
                    TVConnectionScreen(name: "Home · Apple TV", status: .idle, settings: settings, sampledAt: Date()) { _ in }
                case .profiles:
                    TVProfilesScreen(
                        profiles: [PreviewFixtures.profile],
                        selectedID: PreviewFixtures.profile.id,
                        status: .idle,
                        onConnect: { _ in },
                        onEdit: { _ in },
                        onDelete: { _ in },
                        onPair: {},
                        onPaste: {},
                    )
                case .firstRun: TVFirstRunScreen(settings: $settings) {}
                case .empty: TVEmptyProfilesScreen(onPair: {}, onPaste: {})
                case .settings: TVSettingsScreen(settings: $settings, flags: $flags)
                case .pairing, .sas, .expired, .overwrite, .completed:
                    TVPairingScreen(model: TVPairingModel(receiver: TVFakePairingReceiver(value: TVPairingSnapshot(
                        payload: "wgex-pair://v1/00000000-0000-0000-0000-000000000001/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        stage: pairingStage,
                        sas: screen == .sas ? "482917" : nil, attempts: screen == .sas ? 1 : 0,
                    ))))
                case .paste, .review:
                    TVPasteImportScreen(model: paste) { _, _, _ in }
                        .task {
                            if screen == .review {
                                paste.text = "invalid configuration fixture"; paste.prepare()
                            }
                        }
                }
            }
        }
    }

    #Preview("TV Connection Light") { TVScreenPreview(screen: .connection).preferredColorScheme(.light) }
    #Preview("TV Connection Dark") { TVScreenPreview(screen: .connection).preferredColorScheme(.dark) }
    #Preview("TV Profiles Light") { TVScreenPreview(screen: .profiles).preferredColorScheme(.light) }
    #Preview("TV Profiles Dark") { TVScreenPreview(screen: .profiles).preferredColorScheme(.dark) }
    #Preview("TV First Run Light") { TVScreenPreview(screen: .firstRun).preferredColorScheme(.light) }
    #Preview("TV First Run Dark") { TVScreenPreview(screen: .firstRun).preferredColorScheme(.dark) }
    #Preview("TV Empty Light") { TVScreenPreview(screen: .empty).preferredColorScheme(.light) }
    #Preview("TV Empty Dark") { TVScreenPreview(screen: .empty).preferredColorScheme(.dark) }
    #Preview("TV Settings Light") { TVScreenPreview(screen: .settings).preferredColorScheme(.light) }
    #Preview("TV Settings Dark") { TVScreenPreview(screen: .settings).preferredColorScheme(.dark) }
    #Preview("TV Pairing Light") { TVScreenPreview(screen: .pairing).preferredColorScheme(.light) }
    #Preview("TV Pairing Dark") { TVScreenPreview(screen: .pairing).preferredColorScheme(.dark) }
    #Preview("TV SAS Light") { TVScreenPreview(screen: .sas).preferredColorScheme(.light) }
    #Preview("TV SAS Dark") { TVScreenPreview(screen: .sas).preferredColorScheme(.dark) }
    #Preview("TV Expired Light") { TVScreenPreview(screen: .expired).preferredColorScheme(.light) }
    #Preview("TV Expired Dark") { TVScreenPreview(screen: .expired).preferredColorScheme(.dark) }
    #Preview("TV Overwrite Light") { TVScreenPreview(screen: .overwrite).preferredColorScheme(.light) }
    #Preview("TV Overwrite Dark") { TVScreenPreview(screen: .overwrite).preferredColorScheme(.dark) }
    #Preview("TV Received Light") { TVScreenPreview(screen: .completed).preferredColorScheme(.light) }
    #Preview("TV Received Dark") { TVScreenPreview(screen: .completed).preferredColorScheme(.dark) }
    #Preview("TV Paste Light") { TVScreenPreview(screen: .paste).preferredColorScheme(.light) }
    #Preview("TV Paste Dark") { TVScreenPreview(screen: .paste).preferredColorScheme(.dark) }
    #Preview("TV Review Light") { TVScreenPreview(screen: .review).preferredColorScheme(.light) }
    #Preview("TV Review Dark") { TVScreenPreview(screen: .review).preferredColorScheme(.dark) }
#endif
