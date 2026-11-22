// SPDX-License-Identifier: MIT
import SwiftUI
import WGEXCore

/// Native shared editor. The owner performs storage; this view never installs a tunnel.
public struct ProfileEditorForm: View {
    @Bindable private var model: ProfileEditorModel
    private let onSave: (TunnelProfile, borrowing ParsedSecrets) async throws -> Void
    private let onCancel: () -> Void
    private let errorCopy: (any Error) -> String
    private let connectedNetwork: (() async -> ConnectedNetworkReading)?
    private let title: String
    @State private var saveFailure: String?
    @State private var confirmsGeneration = false
    @State private var confirmsForceAll = false
    @State private var copier = SecretCopyController()
    #if os(iOS)
        /// The List's width, from which the cards' side inset on iPad follows.
        @State private var listWidth: CGFloat = 0
    #endif

    /// The save callback must return only after its profile and secret transaction has completed.
    public init(
        model: ProfileEditorModel,
        onSave: @escaping (TunnelProfile, borrowing ParsedSecrets) async throws -> Void,
        onCancel: @escaping () -> Void,
        errorCopy: @escaping (any Error) -> String = { _ in MacStrings.theProfileCouldNotBeSavedCheck },
        connectedNetwork: (() async -> ConnectedNetworkReading)? = nil,
        title: String = EditorStrings.title,
    ) {
        self.model = model; self.onSave = onSave; self.onCancel = onCancel; self.errorCopy = errorCopy
        self.connectedNetwork = connectedNetwork; self.title = title
    }

    public var body: some View {
        container
            .disabled(model.isSaving)
            .navigationTitle(title)
            .toolbar { toolbar }
        #if os(iOS)
            // The title is drawn under the toolbar in title2 bold (the grid's sheet title); the bar keeps only the buttons.
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(removing: .title)
        #endif
            .interactiveDismissDisabled(model.isDirty || model.isSaving)
            .confirmationDialog(EditorStrings.discardWarning, isPresented: $model.showsDiscardConfirmation, titleVisibility: .visible) {
                Button(EditorStrings.discard, role: .destructive, action: onCancel).wgexControl(
                    .editor,
                    "discard",
                    label: EditorStrings.discard,
                )
                Button(EditorStrings.continueEditing, role: .cancel) {}.wgexControl(
                    .editor,
                    "continueEditing",
                    label: EditorStrings.continueEditing,
                )
            }
            .confirmationDialog(EditorStrings.generateWarning, isPresented: $confirmsGeneration, titleVisibility: .visible) {
                Button(EditorStrings.generate) { model.generateKeypair() }.wgexControl(.editor, "generate", label: EditorStrings.generate)
                Button(EditorStrings.cancel, role: .cancel) {}.wgexControl(.editor, "cancel", label: EditorStrings.cancel)
            }
            .sheet(isPresented: $confirmsForceAll) {
                WarningSheet(content: .forceAllTraffic) {
                    model.draft.protection.ios.includeAllNetworks = true; confirmsForceAll = false
                } onCancel: { confirmsForceAll = false }
            }
    }

    /// iOS and iPadOS: the layout C cards on the form grid as a List, so the server rows keep Edit's reordering; labels and
    /// fields in subheadline; switches end on the right line; group headings a step above their cards, 12 pt under the
    /// card before. On iPad the cards stop at the grid's form width, centred, while the List (and its scrolling) keeps the
    /// full width. tvOS and macOS: the system form, as before.
    private var container: some View {
        #if os(iOS)
            List {
                Section {} header: {
                    Text(title).font(IOSDesign.sheetTitle).foregroundStyle(IOSDesign.text).textCase(nil)
                        .accessibilityAddTraits(.isHeader).iosListHeader()
                }
                sections
            }
            // Before iosCardList, so the grid's subheadline and section spacing win over the list's.
            .font(IOSDesign.field)
            .listSectionSpacing(IOSDesign.Grid.headingAbove)
            .iosCardList()
            .environment(\.defaultMinListHeaderHeight, 0)
            .toggleStyle(IOSRowToggleStyle())
            .environment(\.iosListSideInset, max(0, (listWidth - IOSDesign.Grid.formMaxWidth) / 2 - IOSDesign.Grid.screenMargin))
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { listWidth = $0 }
        #else
            ScrollView { Form { sections } }
        #endif
    }

    @ViewBuilder private var sections: some View {
        interfaceSection
        peersSection
        protectionSection
        #if os(iOS)
            IOSOnDemandSection(model: model, connectedNetwork: connectedNetwork)
        #endif
        #if os(macOS)
            MacOnDemandSection(model: model, connectedNetwork: connectedNetwork)
            macSection
        #endif
        if model.featureFlags.relayTransports {
            editorSection(EditorStrings.transports) {
                Text(EditorStrings.udp)
                EditorFieldBadge(model: model, field: .transport)
            }
        }
        diagnosticsSection
    }

    private var diagnosticsSection: some View {
        editorSection(EditorStrings.diagnostics, showsHeader: hasDiagnostics) {
            EditorDiagnosticsView(model.diagnostics.map(\.diagnostic))
            if !model.canSave {
                EditorMessage(EditorStrings.saveBlocked)
            }
            if let saveFailure {
                EditorMessage(saveFailure)
            }
            if model.actionFailed {
                EditorMessage(EditorStrings.generationFailed)
            }
        }
    }

    private var hasDiagnostics: Bool {
        !model.diagnostics.isEmpty || !model.canSave || saveFailure != nil || model.actionFailed
    }

    private var peersSection: some View {
        #if os(iOS)
            iosPeersSection
        #else
            otherPeersSection
        #endif
    }

    private var otherPeersSection: some View {
        Section(EditorStrings.peers) {
            #if !os(tvOS)
                ForEach($model.draft.peers) { $peer in
                    peerFields($peer)
                }
                .onMove { model.movePeers(from: $0, to: $1) }
            #else
                ForEach($model.draft.peers) { $peer in peerFields($peer) }
            #endif
            Button(EditorStrings.addPeer) { model.addPeer() }.wgexControl(.editor, "addPeer", label: EditorStrings.addPeer)
            EditorFieldBadge(model: model, field: .peers)
        }
    }

    private func peerFields(_ peer: Binding<PeerEditorDraft>) -> some View {
        let id = peer.wrappedValue.id
        return EditorPeerStack {
            field(EditorStrings.publicKey, text: peer.publicKey, target: .publicKey(id), monospaced: true)
            SecretField(EditorStrings.presharedKey, copier: copier, onCommit: { try model.setPresharedKey($0, peerID: id) }) {
                model.presharedKeyForField(peerID: id)
            }
            EditorFieldBadge(model: model, field: .presharedKey(id))
            if peer.wrappedValue.presharedReference != nil {
                Button(EditorStrings.clearPSK) { model.removePresharedKey(peerID: id) }.wgexControl(
                    .editor,
                    "clearPSK",
                    label: EditorStrings.clearPSK,
                )
                .editorButton(.secondary)
            }
            EndpointField(
                EditorStrings.endpoint,
                text: peer.endpoint,
                validation: ProfileEditorModel.endpointValidation(peer.wrappedValue.endpoint),
            )
            EditorFieldBadge(model: model, field: .endpoint(id))
            AllowedIPsEditor(model: peer.allowedIPs, dnsServers: ProfileEditorModel.parts(model.draft.dns))
            EditorFieldBadge(model: model, field: .allowedIPs(id))
            EditorMessage(EditorStrings.privateRanges, tone: .note)
            field(EditorStrings.keepalive, text: peer.keepalive, target: .keepalive(id))
            #if !os(tvOS)
                HStack {
                    Button(EditorStrings.moveUp) { move(id, down: false) }.wgexControl(.editor, "moveUp", label: EditorStrings.moveUp)
                        .disabled(model.draft.peers.first?.id == id)
                    Button(EditorStrings.moveDown) { move(id, down: true) }.wgexControl(.editor, "moveDown", label: EditorStrings.moveDown)
                        .disabled(model.draft.peers.last?.id == id)
                }
                .editorButton(.secondary)
            #endif
            Button(EditorStrings.removePeer, role: .destructive) { model.removePeer(id: id) }.wgexControl(
                .editor,
                "removePeer",
                label: EditorStrings.removePeer,
            )
            .editorButton(.destructive)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(EditorStrings.peer((model.draft.peers.firstIndex { $0.id == id } ?? 0) + 1))
    }

    private var protectionSection: some View {
        editorSection(EditorStrings.protection) {
            pickerRow(EditorStrings.ipv6) {
                Picker(EditorStrings.ipv6, selection: $model.draft.protection.ipv6Policy) {
                    Text(EditorStrings.tunnelIPv6).tag(IPv6Policy.tunnel)
                    Text(EditorStrings.blockIPv6).tag(IPv6Policy.blockOutside)
                    Text(EditorStrings.allowIPv6).tag(IPv6Policy.allowOutside)
                }.wgexControl(.editor, "ipv6", label: EditorStrings.ipv6)
            }
            EditorFieldBadge(model: model, field: .ipv6Policy)
            pickerRow(EditorStrings.dnsPolicy) {
                Picker(EditorStrings.dnsPolicy, selection: dnsSelection) {
                    Text(EditorStrings.tunnelDNS).tag(0)
                    Text(EditorStrings.splitDNS).tag(1)
                    Text(EditorStrings.systemDNS).tag(2)
                }.wgexControl(.editor, "dnsPolicy", label: EditorStrings.dnsPolicy)
            }
            if case .split = model.draft.protection.dnsPolicy {
                splitDomainsField
            }
            EditorFieldBadge(model: model, field: .dnsPolicy)
            #if os(iOS)
                Toggle(EditorStrings.forceAll, isOn: Binding(get: { model.draft.protection.ios.includeAllNetworks }, set: {
                    if $0 {
                        confirmsForceAll = true
                    } else {
                        model.draft.protection.ios.includeAllNetworks = false
                    }
                })).wgexControl(.editor, "forceAll", label: EditorStrings.forceAll)
                Toggle(EditorStrings.allowLAN, isOn: $model.draft.protection.ios.excludeLocalNetworks).wgexControl(
                    .editor,
                    "allowLAN",
                    label: EditorStrings
                        .allowLAN,
                )
                Toggle(EditorStrings.cellular, isOn: $model.draft.protection.ios.excludeCellularServices).wgexControl(
                    .editor,
                    "cellular",
                    label: EditorStrings
                        .cellular,
                )
                Toggle(EditorStrings.apns, isOn: $model.draft.protection.ios.excludeAPNs).wgexControl(
                    .editor,
                    "apns",
                    label: EditorStrings.apns,
                )
                Toggle(EditorStrings.communication, isOn: $model.draft.protection.ios.excludeDeviceCommunication).wgexControl(
                    .editor,
                    "communication",
                    label: EditorStrings.communication,
                )
                EditorMessage(EditorStrings.exclusions, tone: .note)
            #elseif os(tvOS)
                Toggle(EditorStrings.allowLAN, isOn: $model.draft.protection.tv.allowLAN).wgexControl(
                    .editor,
                    "allowLAN",
                    label: EditorStrings.allowLAN,
                )
                Text(UserStrings.tvProtection).font(.caption)
            #endif
        }
    }
}

private extension ProfileEditorForm {
    var interfaceSection: some View {
        editorSection(EditorStrings.interface) {
            field(EditorStrings.name, text: $model.draft.name, target: .name)
            #if os(iOS)
                // The grid: Generate joins Update key on the private key's action row.
                SecretField(
                    EditorStrings.privateKey, copier: copier, onCommit: { try model.setPrivateKey($0) },
                    moreActions: AnyView(generateButton),
                ) {
                    model.privateKeyForField()
                }
                EditorFieldBadge(model: model, field: .privateKey).iosRowKind(.caption)
                // As the LabeledContent line was: a container with the key text as its own child.
                IOSValueRow { publicKeyText } label: { Text(EditorStrings.publicKey) }
                    .accessibilityElement(children: .contain)
                    .wgexAX(.editor, "publicKey", label: EditorStrings.publicKey)
            #else
                SecretField(EditorStrings.privateKey, copier: copier, onCommit: { try model.setPrivateKey($0) }) {
                    model.privateKeyForField()
                }
                EditorFieldBadge(model: model, field: .privateKey)
                generateButton.editorButton(.secondary)
                LabeledContent(EditorStrings.publicKey) { publicKeyText }.wgexAX(
                    .editor,
                    "publicKey",
                    label: EditorStrings
                        .publicKey,
                )
            #endif
            field(EditorStrings.addresses, text: $model.draft.addresses, target: .addresses)
            field(EditorStrings.listenPort, text: $model.draft.listenPort, target: .listenPort)
            field(EditorStrings.mtu, text: $model.draft.mtu, target: .mtu)
            field(EditorStrings.dns, text: $model.draft.dns, target: .dns)
            field(EditorStrings.searchDomains, text: $model.draft.searchDomains, target: .searchDomains)
        }
    }

    /// Generate keypair; on iOS its visible title is "Generate" and its accessibility label stays the long one.
    var generateButton: some View {
        Button(generateTitle) {
            if model.needsPrivateKey {
                model.generateKeypair()
            } else {
                confirmsGeneration = true
            }
        }.wgexControl(.editor, "generateKeypair", label: EditorStrings.generate)
    }

    private var generateTitle: String {
        #if os(iOS)
            PlatformStrings.editorGenerate
        #else
            EditorStrings.generate
        #endif
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        #if os(iOS)
            // Layout C: the sheet's own buttons, without the toolbar's glass capsules; Edit and Save one button gap apart,
            // and on iPad at the screen margin as on iPhone. Their text stops growing at the first accessibility size, so
            // all three keep their place in the bar.
            ToolbarItem(placement: .cancellationAction) {
                cancelButton.buttonStyle(.iosSecondary).fixedSize().dynamicTypeSize(...Self.toolbarTypeLimit)
                    .padding(.leading, Self.barMargin)
            }
            .sharedBackgroundVisibility(.hidden)
            ToolbarItem(placement: .confirmationAction) {
                HStack(spacing: IOSDesign.Grid.buttonGap) {
                    EditButton().buttonStyle(.iosSecondary)
                    saveButton.buttonStyle(.iosPrimary)
                }
                .fixedSize().dynamicTypeSize(...Self.toolbarTypeLimit)
                .padding(.trailing, Self.barMargin)
            }
            .sharedBackgroundVisibility(.hidden)
        #else
            ToolbarItem(placement: .cancellationAction) { cancelButton.buttonStyle(.glass) }
            ToolbarItem(placement: .confirmationAction) { saveButton.buttonStyle(.glassProminent) }
        #endif
    }

    #if os(iOS)
        private static let toolbarTypeLimit = DynamicTypeSize.accessibility1

        /// What the toolbar buttons add to the system bar's side inset to sit at the screen margin: nothing on iPhone,
        /// whose bar inset is the margin already.
        @MainActor private static var barMargin: CGFloat {
            UIDevice.current.userInterfaceIdiom == .pad ? IOSDesign.Grid.screenMargin - IOSDesign.Grid.padBarInset : 0
        }
    #endif

    private var cancelButton: some View {
        Button(EditorStrings.cancel) {
            if model.requestDiscard() {
                onCancel()
            }
        }.wgexControl(.editor, "cancelChanges", label: EditorStrings.cancel)
    }

    private var saveButton: some View {
        Button(EditorStrings.save, action: save).wgexControl(.editor, "save", label: EditorStrings.save)
            .disabled(!model.canSave || model.isSaving)
    }

    /// The interface's public key: monospaced; on iOS on one line, shortened in the middle, as the Mac shows it.
    var publicKeyText: some View {
        #if os(iOS)
            Text(model.publicKey.base64).font(IOSDesign.key).lineLimit(1).truncationMode(.middle)
        #else
            Text(model.publicKey.base64).font(Typography.code)
        #endif
    }

    /// iOS: a pop-up row whose value keeps its own width (the label gives way); elsewhere the picker as it was.
    func pickerRow(_ title: String, @ViewBuilder picker: () -> some View) -> some View {
        #if os(iOS)
            IOSControlRow { picker().iosMenuPicker() } label: { Text(title) }
        #else
            picker()
        #endif
    }

    #if os(macOS)
        private var macSection: some View {
            Section(EditorStrings.macOptions) {
                Toggle(EditorStrings.boot, isOn: Binding(get: { model.draft.macOptions.startBeforeLogin }, set: {
                    model.draft.macOptions.startBeforeLogin = $0
                    if $0 {
                        model.draft.macOptions.autoConnectAtLogin = false
                    }
                })).wgexControl(.editor, "boot", label: EditorStrings.boot)
                Text(EditorStrings.bootWarning).font(.caption)
                Text(EditorStrings.fileVault).font(.caption)
                Toggle(EditorStrings.login, isOn: Binding(get: { model.draft.macOptions.autoConnectAtLogin }, set: {
                    model.draft.macOptions.autoConnectAtLogin = $0
                    if $0 {
                        model.draft.macOptions.startBeforeLogin = false
                    }
                })).wgexControl(.editor, "login", label: EditorStrings.login)
            }
        }
    #endif

    /// `monospaced` sets a key in monospaced type on iOS; `label` is a shorter visible label (and placeholder) on the iOS
    /// grid, the title staying the accessibility label; `unit` sits at the end of the iOS field box. Other platforms keep
    /// their look.
    private func field(
        _ title: String, text: Binding<String>, target: EditorField, monospaced: Bool = false, label: String? = nil,
        unit: String? = nil,
    ) -> some View {
        VStack(alignment: .leading) {
            #if os(iOS)
                IOSFieldRow {
                    TextField(title, text: text, prompt: iosFieldPrompt(label ?? title))
                        .font(monospaced ? IOSDesign.key : IOSDesign.field)
                        .wgexControl(.editor, "field", label: title, item: target.automationKey).autocorrectionDisabled()
                        .accessibilityLabel(title)
                        .textInputAutocapitalization(.never)
                } accessory: {
                    if let unit {
                        IOSFieldUnit(unit)
                    }
                } label: {
                    Text(label ?? title)
                }
            #else
                TextField(title, text: text).wgexControl(.editor, "field", label: title, item: target.automationKey)
                    .autocorrectionDisabled()
                    .accessibilityLabel(title)
                #if os(tvOS)
                    .textInputAutocapitalization(.never)
                #endif
            #endif
            EditorFieldBadge(model: model, field: target)
        }
    }

    @ViewBuilder private var splitDomainsField: some View {
        let field = TextField(EditorStrings.splitDomains, text: splitDomains).wgexControl(
            .editor,
            "splitDomains",
            label: EditorStrings.splitDomains,
        )
        #if os(iOS)
            IOSFieldRow { field } label: { Text(EditorStrings.splitDomains) }
        #else
            field
        #endif
    }

    /// A section of the editor: on iOS a layout C card under a group heading (none when `showsHeader` is false, so an
    /// empty card leaves no heading behind); elsewhere the system section.
    func editorSection(
        _ title: String, showsHeader: Bool = true, @ViewBuilder content: () -> some View,
    ) -> some View {
        #if os(iOS)
            Section {
                IOSListCardRows(content: content)
            } header: {
                if showsHeader {
                    IOSGroupHeading(title).iosGridHeader()
                }
            }
        #else
            Section(title, content: content)
        #endif
    }

    private var dnsSelection: Binding<Int> {
        Binding(get: {
            switch model.draft.protection.dnsPolicy { case .tunnelAll: 0; case .split: 1; case .systemDefault: 2 }
        }, set: {
            switch $0 { case 1: model.draft.protection.dnsPolicy = .split([])
            case 2: model.draft.protection.dnsPolicy = .systemDefault
            default: model.draft.protection.dnsPolicy = .tunnelAll }
        })
    }

    private var splitDomains: Binding<String> {
        Binding(get: {
            if case let .split(domains) = model.draft.protection.dnsPolicy {
                return domains.joined(separator: ", ")
            }
            return ""
        }, set: { model.draft.protection.dnsPolicy = .split(ProfileEditorModel.parts($0)) })
    }

    private func move(_ id: UUID, down: Bool) {
        guard let index = model.draft.peers.firstIndex(where: { $0.id == id }) else { return }
        model.movePeers(from: IndexSet(integer: index), to: down ? index + 2 : index - 1)
    }

    private func save() {
        Task {
            do { try await model.save(using: onSave); saveFailure = nil }
            catch { saveFailure = errorCopy(error) }
        }
    }
}

#if os(iOS)
    private extension ProfileEditorForm {
        /// The servers as card rows set by hand, so the ForEach keeps Edit's reordering: one row per server, then the
        /// list's own problems when it has any; Add peer is an accent row in its own card below.
        @ViewBuilder var iosPeersSection: some View {
            let peers = model.draft.peers
            let showsBadge = !model.diagnostics(for: .peers).isEmpty
            let count = peers.count + (showsBadge ? 1 : 0)
            Section {
                ForEach($model.draft.peers) { $peer in
                    iosPeerRows($peer)
                        .iosCardRow(IOSCardRowPosition(index: peers.firstIndex { $0.id == peer.id } ?? 0, count: count))
                }
                .onMove { model.movePeers(from: $0, to: $1) }
                if showsBadge {
                    EditorFieldBadge(model: model, field: .peers).iosCardRow(IOSCardRowPosition(index: count - 1, count: count))
                }
            } header: {
                IOSGroupHeading(EditorStrings.peers).iosGridHeader()
            }
            Section {
                Button(EditorStrings.addPeer) { model.addPeer() }.wgexControl(.editor, "addPeer", label: EditorStrings.addPeer)
                    .buttonStyle(.iosRowAction)
                    .iosCardRow(.only)
            }
        }

        /// One server on the grid: its fields, the key and address action rows, Move up and Move down, and Remove peer.
        func iosPeerRows(_ peer: Binding<PeerEditorDraft>) -> some View {
            let id = peer.wrappedValue.id
            return IOSSubRows {
                field(EditorStrings.publicKey, text: peer.publicKey, target: .publicKey(id), monospaced: true)
                SecretField(
                    EditorStrings.presharedKey, copier: copier, onCommit: { try model.setPresharedKey($0, peerID: id) },
                    moreActions: peer.wrappedValue.presharedReference == nil ? nil : AnyView(clearPSKButton(id)),
                ) {
                    model.presharedKeyForField(peerID: id)
                }
                EditorFieldBadge(model: model, field: .presharedKey(id)).iosRowKind(.caption)
                EndpointField(
                    EditorStrings.endpoint,
                    text: peer.endpoint,
                    validation: ProfileEditorModel.endpointValidation(peer.wrappedValue.endpoint),
                )
                EditorFieldBadge(model: model, field: .endpoint(id)).iosRowKind(.caption)
                AllowedIPsEditor(model: peer.allowedIPs, dnsServers: ProfileEditorModel.parts(model.draft.dns))
                EditorFieldBadge(model: model, field: .allowedIPs(id)).iosRowKind(.caption)
                EditorMessage(EditorStrings.privateRanges, tone: .note)
                field(
                    EditorStrings.keepalive, text: peer.keepalive, target: .keepalive(id), label: PlatformStrings.editorKeepalive,
                    unit: PlatformStrings.editorSeconds,
                )
                IOSActionRow {
                    Button(PlatformStrings.editorMoveUp) { move(id, down: false) }
                        .wgexControl(.editor, "moveUp", label: EditorStrings.moveUp)
                        .disabled(model.draft.peers.first?.id == id)
                    Button(PlatformStrings.editorMoveDown) { move(id, down: true) }
                        .wgexControl(.editor, "moveDown", label: EditorStrings.moveDown)
                        .disabled(model.draft.peers.last?.id == id)
                }
                Button(EditorStrings.removePeer, role: .destructive) { model.removePeer(id: id) }.wgexControl(
                    .editor,
                    "removePeer",
                    label: EditorStrings.removePeer,
                )
                .buttonStyle(.iosDestructive)
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel(EditorStrings.peer((model.draft.peers.firstIndex { $0.id == id } ?? 0) + 1))
        }

        func clearPSKButton(_ id: UUID) -> some View {
            Button(EditorStrings.clearPSK) { model.removePresharedKey(peerID: id) }.wgexControl(
                .editor,
                "clearPSK",
                label: EditorStrings.clearPSK,
            )
        }
    }
#endif
