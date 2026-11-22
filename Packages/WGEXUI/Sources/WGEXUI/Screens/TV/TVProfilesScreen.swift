// SPDX-License-Identifier: MIT

#if os(tvOS)
    import SwiftUI
    import WGEXCore

    public struct TVProfilesScreen: View {
        public var profiles: [TunnelProfile]
        public var selectedID: UUID?
        public var status: TunnelStatus
        public var onConnect: (TunnelProfile) -> Void
        public var onEdit: (TunnelProfile) -> Void
        public var onDelete: (TunnelProfile) -> Void
        public var onPair: () -> Void
        public var onPaste: () -> Void
        @State private var deleting: TunnelProfile?
        @FocusState private var focusedProfile: UUID?
        @Namespace private var focus

        public init(
            profiles: [TunnelProfile],
            selectedID: UUID?,
            status: TunnelStatus,
            onConnect: @escaping (TunnelProfile) -> Void,
            onEdit: @escaping (TunnelProfile) -> Void,
            onDelete: @escaping (TunnelProfile) -> Void,
            onPair: @escaping () -> Void,
            onPaste: @escaping () -> Void,
        ) {
            self.profiles = profiles; self.selectedID = selectedID; self.status = status
            self.onConnect = onConnect; self.onEdit = onEdit; self.onDelete = onDelete
            self.onPair = onPair; self.onPaste = onPaste
        }

        public var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 40) {
                    Text("Profiles").font(.largeTitle.bold())
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 400))], spacing: 40) {
                        ForEach(profiles) { profile in
                            VStack(spacing: 24) {
                                Button { onConnect(profile) } label: {
                                    ProfileCard(summary: ProfileSummary(
                                        id: profile.id,
                                        name: profile.name,
                                        endpoint: profile.peers.first?.endpoint,
                                        peerCount: profile.peers.count,
                                        verdict: profile.id == selectedID ? TVConnectionState
                                            .presentation(status).verdict : nil,
                                    ))
                                    .padding(20)
                                }
                                .buttonStyle(.card)
                                .focused($focusedProfile, equals: profile.id)
                                .prefersDefaultFocus(profile.id == selectedID, in: focus)
                                .accessibilityHint("Connect this profile")
                                HStack {
                                    Button("Edit") { onEdit(profile) }.accessibilityLabel("Edit \(profile.name)")
                                    Button("Delete", role: .destructive) { deleting = profile }
                                        .accessibilityLabel("Delete \(profile.name)")
                                }
                            }.focusSection()
                        }
                        VStack(spacing: 24) {
                            Button(action: onPair) { Label("Add from iPhone or Mac", systemImage: "qrcode").padding(40) }
                                .buttonStyle(.card)
                            Button("Paste a configuration", action: onPaste)
                        }.focusSection()
                    }
                    Text("Use a separate configuration for each device.").foregroundStyle(.secondary)
                }.padding(60)
            }
            .focusScope(focus)
            .defaultFocus($focusedProfile, selectedID)
            .confirmationDialog(
                "Delete this profile?",
                isPresented: Binding(get: { deleting != nil }, set: {
                    if !$0 {
                        deleting = nil
                    }
                }),
                titleVisibility: .visible,
            ) {
                Button("Delete profile", role: .destructive) {
                    if let deleting {
                        onDelete(deleting)
                    }; deleting = nil
                }
                Button("Cancel", role: .cancel) { deleting = nil }
            } message: { Text("The profile and its saved keys will be removed from this Apple TV.") }
        }
    }
#endif
