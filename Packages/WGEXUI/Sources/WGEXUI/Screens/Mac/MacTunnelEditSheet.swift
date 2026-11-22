// SPDX-License-Identifier: MIT

#if os(macOS)
    import AppKit
    import Combine
    import SwiftUI
    import WGEXCore

    /// The Mac Edit sheet (SPEC 6.3) on the shared editor model: "Edit <name>", grouped rows, a click-to-reveal private key,
    /// one Server group per peer, and Edit as Text. Both views edit the same tunnel and Save validates either. The owner
    /// performs storage; this view never installs a tunnel.
    public struct MacTunnelEditSheet: View {
        @Bindable private var model: ProfileEditorModel
        private let onSave: (TunnelProfile, borrowing ParsedSecrets) async throws -> Void
        private let onCancel: () -> Void
        private let errorCopy: (any Error) -> String
        private let connectedNetwork: (() async -> ConnectedNetworkReading)?
        private let opensAsText: Bool
        private let height: CGFloat
        @State private var session = MacTextSession()
        @State private var saveFailure: String?

        /// The save callback must return only after its profile and secret transaction has completed. `opensAsText` opens
        /// the sheet in Edit as Text and `height` makes it taller, for previews and picture tests.
        public init(
            model: ProfileEditorModel,
            onSave: @escaping (TunnelProfile, borrowing ParsedSecrets) async throws -> Void,
            onCancel: @escaping () -> Void,
            errorCopy: @escaping (any Error) -> String = { _ in MacStrings.theProfileCouldNotBeSavedCheck },
            connectedNetwork: (() async -> ConnectedNetworkReading)? = nil,
            opensAsText: Bool = false,
            height: CGFloat = 680,
        ) {
            self.model = model; self.onSave = onSave; self.onCancel = onCancel; self.errorCopy = errorCopy
            self.connectedNetwork = connectedNetwork; self.opensAsText = opensAsText; self.height = height
        }

        public var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(MacDesign.pageTitle).foregroundStyle(MacDesign.text).lineLimit(1).truncationMode(.middle)
                    .padding(.horizontal, MacDesign.Space.page).padding(.top, 18)
                if session.isActive {
                    MacEditAsTextView(text: $session.text).padding(MacDesign.Space.page)
                } else {
                    MacTunnelEditForm(model: model, connectedNetwork: connectedNetwork)
                }
                problemList
                footer.padding(.horizontal, MacDesign.Space.page).padding(.bottom, 16)
            }
            .buttonStyle(.macSecondary)
            .tint(MacDesign.accent)
            .frame(width: 640, height: height)
            .background(MacDesign.pageBackground)
            .disabled(model.isSaving)
            .interactiveDismissDisabled(model.isDirty || model.isSaving || session.isEdited)
            .confirmationDialog(
                MacStrings.tunnelChangesWillBeLost,
                isPresented: $model.showsDiscardConfirmation,
                titleVisibility: .visible,
            ) {
                Button(MacStrings.discardChangesAction, role: .destructive, action: close)
                    .wgexControl(.editor, "discard", label: MacStrings.discardChangesAction)
                Button(MacStrings.keepEditingAction, role: .cancel) {}
                    .wgexControl(.editor, "continueEditing", label: MacStrings.keepEditingAction)
            }
            .onDisappear { session.close() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                session.leave(model)
            }
            .macOnWindowLeave { session.leave(model) }
            .task {
                if opensAsText, !session.isActive {
                    showText()
                }
            }
            .accessibilityElement(children: .contain)
        }

        private var title: String {
            model.sourceProfile.name.isEmpty ? MacStrings.newTunnelTitle : MacStrings.editTunnelTitle(model.sourceProfile.name)
        }

        // MARK: Problems and buttons

        private var problems: [String] {
            var lines = session.notice + (session.isActive ? session.problems : MacTunnelProblems.lines(
                model.diagnostics.map(\.diagnostic), nameIsEmpty: model.draft.name.isEmpty,
            ))
            if let saveFailure {
                lines.append(saveFailure)
            }
            if model.actionFailed {
                lines.append(MacStrings.aKeypairCouldNotBeGeneratedTry)
            }
            return lines
        }

        /// Lines that come from a warning of the model's own checks (and from no error): shown in caution, the rest in error.
        private var warningLines: Set<String> {
            let issues = model.diagnostics.map(\.diagnostic)
            let nameIsEmpty = model.draft.name.isEmpty
            let texts = { (severity: ConfigDiagnostic.Severity) in
                Set(issues.filter { $0.severity == severity }.map { MacTunnelProblems.text($0, nameIsEmpty: nameIsEmpty) })
            }
            return texts(.warning).subtracting(texts(.error))
        }

        /// Lines that are already captions under their row in the form: the list leaves them out (it keeps a line that also
        /// comes from a problem with no row). In Edit as Text every line is listed.
        private func rowCaptioned(_ lines: [String]) -> Set<String> {
            guard !session.isActive else { return [] }
            let issues = model.diagnostics
            let nameIsEmpty = model.draft.name.isEmpty
            let texts = { (atRow: Bool) in
                Set(issues.filter { $0.fields.contains(where: MacFieldCaptions.isShownAtRow) == atRow }
                    .map { MacTunnelProblems.text($0.diagnostic, nameIsEmpty: nameIsEmpty) })
            }
            return Set(lines).intersection(texts(true).subtracting(texts(false)))
        }

        /// The problems without a row of their own (text, save and key-pair problems, and checks of the whole tunnel), under
        /// the form. The element keeps every line in its label, as it always has, also when all of them are row captions.
        @ViewBuilder private var problemList: some View {
            let lines = problems
            if !lines.isEmpty {
                let warnings = warningLines
                let captioned = rowCaptioned(lines)
                let listed = lines.filter { !captioned.contains($0) }
                Group {
                    if listed.isEmpty {
                        Color.clear.frame(maxWidth: .infinity).frame(height: 1)
                    } else {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(listed, id: \.self) { line in
                                    MacRowCaption(line, tone: warnings.contains(line) ? .caution : .error)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 76).fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, MacDesign.Space.page).padding(.top, 6).padding(.bottom, 10)
                    }
                }
                .accessibilityElement(children: .combine)
                .wgexAX(.editor, "problems", label: lines.joined(separator: " "))
            }
        }

        private var footer: some View {
            HStack(spacing: 8) {
                if !session.isActive {
                    Button(MacStrings.addServer) { model.addPeer() }
                        .wgexControl(.editor, "addPeer", label: MacStrings.addServer).lineLimit(1)
                    Button(MacStrings.editAsText, action: showText)
                        .wgexControl(.editor, "editAsText", label: MacStrings.editAsText).lineLimit(1)
                        .disabled(!model.canEditAsText)
                } else {
                    Button(MacStrings.editAsForm, action: showForm)
                        .wgexControl(.editor, "editAsForm", label: MacStrings.editAsForm).lineLimit(1)
                }
                Spacer()
                Button(MacStrings.cancel, action: cancel)
                    .wgexControl(.editor, "cancelChanges", label: MacStrings.cancel)
                    .keyboardShortcut(.cancelAction).lineLimit(1)
                Button(MacStrings.save, action: save)
                    .wgexControl(.editor, "save", label: MacStrings.save)
                    .buttonStyle(.macPrimary).keyboardShortcut(.defaultAction).lineLimit(1)
                    .disabled(model.isSaving || (session.isActive ? session.text.isEmpty : !model.canSave))
            }
        }

        // MARK: Actions

        private func showText() {
            do {
                try session.open(model)
                saveFailure = nil
            } catch { saveFailure = errorCopy(error) }
        }

        /// Returns to the form when the text parses; otherwise the text view stays and lists the problem.
        private func showForm() {
            _ = session.returnToForm(model)
        }

        private func save() {
            if session.isActive {
                guard session.apply(to: model) else { return }
                guard model.canSave else {
                    session.saveBlocked(model)
                    return
                }
            }
            Task {
                do {
                    try await model.save(using: onSave)
                    saveFailure = nil
                    session.saved()
                } catch { saveFailure = errorCopy(error) }
            }
        }

        private func cancel() {
            if model.isDirty || session.isEdited {
                model.showsDiscardConfirmation = true
            } else {
                close()
            }
        }

        private func close() {
            session.close()
            onCancel()
        }
    }

    /// The grouped form of the Edit sheet. Below the SPEC 6.3 groups (the first group and one Server group per peer) it keeps
    /// every editor capability: listen port, MTU, search domains, preshared keys, IPv6 and DNS policy, exclusions, on-demand and
    /// start-up.
    package struct MacTunnelEditForm: View {
        @Bindable package var model: ProfileEditorModel
        package let connectedNetwork: (() async -> ConnectedNetworkReading)?
        @State private var confirmsGeneration = false

        package var body: some View {
            Form {
                Section {
                    field(MacStrings.name, text: $model.draft.name, target: .name)
                    MacCaptionedRow(model: model, field: .privateKey) {
                        MacKeyRow(
                            MacStrings.privateKey, key: .privateKey, hasKey: !model.needsPrivateKey,
                            resetToken: model.keyResetRevision,
                            load: { model.privateKeyForField() }, commit: { try model.setPrivateKey($0) },
                        )
                    }
                    LabeledContent(MacStrings.publicKey) {
                        Text(model.publicKey.base64).font(MacDesign.body.monospaced()).lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                    }.wgexAX(.editor, "publicKey", label: MacStrings.publicKey)
                    Button(MacStrings.generateKeyPair, action: generate)
                        .wgexControl(.editor, "generateKeypair", label: MacStrings.generateKeyPair).lineLimit(1)
                    field(MacStrings.addresses, text: $model.draft.addresses, target: .addresses)
                    field(MacStrings.dns, text: $model.draft.dns, target: .dns)
                }
                ForEach(Array(model.draft.peers.enumerated()), id: \.element.id) { index, peer in
                    MacServerSection(model: model, peerID: peer.id, number: model.draft.peers.count > 1 ? index + 1 : nil)
                }
                Section(MacStrings.advanced) {
                    field(MacStrings.listenPort, text: $model.draft.listenPort, target: .listenPort)
                    field(MacStrings.mtu, text: $model.draft.mtu, target: .mtu)
                    field(MacStrings.searchDomains, text: $model.draft.searchDomains, target: .searchDomains)
                }
                MacTunnelProtectionSection(model: model)
                // Its own file is not part of the restyle: the card's bordered field reaches it from here.
                MacExclusionsSection(model: model).textFieldStyle(.roundedBorder)
                MacOnDemandSection(model: model, connectedNetwork: connectedNetwork)
                startUpSection
            }
            .formStyle(.macCards)
            .confirmationDialog(MacStrings.newKeyPairWarning, isPresented: $confirmsGeneration, titleVisibility: .visible) {
                Button(MacStrings.generateKeyPair) { model.generateKeypair() }
                    .wgexControl(.editor, "generate", label: MacStrings.generateKeyPair)
                Button(MacStrings.cancel, role: .cancel) {}.wgexControl(.editor, "cancel", label: MacStrings.cancel)
            }
        }

        private var startUpSection: some View {
            Section(MacStrings.startUp) {
                VStack(alignment: .leading, spacing: 2) {
                    MacSwitchRow(MacStrings.startBeforeLogin) {
                        Toggle(MacStrings.startBeforeLogin, isOn: Binding(get: { model.draft.macOptions.startBeforeLogin }, set: {
                            model.draft.macOptions.startBeforeLogin = $0
                            if $0 {
                                model.draft.macOptions.autoConnectAtLogin = false
                            }
                        })).wgexControl(.editor, "boot", label: MacStrings.startBeforeLogin)
                    }
                    MacRowCaption(MacStrings.startingBeforeLoginRequires)
                }
                MacSwitchRow(MacStrings.connectAtLogin) {
                    Toggle(MacStrings.connectAtLogin, isOn: Binding(get: { model.draft.macOptions.autoConnectAtLogin }, set: {
                        model.draft.macOptions.autoConnectAtLogin = $0
                        if $0 {
                            model.draft.macOptions.startBeforeLogin = false
                        }
                    })).wgexControl(.editor, "login", label: MacStrings.connectAtLogin)
                }
            }
        }

        private func generate() {
            if model.needsPrivateKey {
                model.generateKeypair()
            } else {
                confirmsGeneration = true
            }
        }

        private func field(_ title: String, text: Binding<String>, target: EditorField) -> some View {
            MacCaptionedRow(model: model, field: target) { MacEditField(title: title, text: text, target: target) }
        }
    }

    /// One Server group (SPEC 6.3): Public key, Endpoint, Allowed IPs, Keepalive, then the preshared key and Remove Server.
    package struct MacServerSection: View {
        @Bindable package var model: ProfileEditorModel
        package let peerID: UUID
        /// Shown as "Server 1", "Server 2" when the tunnel has more than one server.
        package let number: Int?

        package var body: some View {
            if let index = model.draft.peers.firstIndex(where: { $0.id == peerID }) {
                let peer = $model.draft.peers[index]
                Section(number.map { MacStrings.serverNumber($0) } ?? MacStrings.server) {
                    MacCaptionedRow(model: model, field: .publicKey(peerID)) {
                        MacEditField(title: MacStrings.publicKey, text: peer.publicKey, target: .publicKey(peerID), monospaced: true)
                    }
                    MacCaptionedRow(model: model, field: .endpoint(peerID)) {
                        MacEditField(title: MacStrings.endpoint, text: peer.endpoint, target: .endpoint(peerID))
                    }
                    MacCaptionedRow(model: model, field: .allowedIPs(peerID)) {
                        MacAllowedIPsField(model: peer.allowedIPs, target: .allowedIPs(peerID))
                    }
                    if peer.wrappedValue.allowedIPs.privateNetworkExclusion(dnsServers: dnsServers) != .unavailable {
                        MacSwitchRow(MacStrings.excludePrivateNetworks) {
                            Toggle(MacStrings.excludePrivateNetworks, isOn: Binding(
                                get: { peer.wrappedValue.allowedIPs.privateNetworkExclusion(dnsServers: dnsServers) == .on },
                                set: { model.setPrivateNetworksExcluded($0, peerID: peerID) },
                            )).wgexControl(.editor, "excludePrivateNetworks", label: MacStrings.excludePrivateNetworks)
                        }
                    }
                    MacCaptionedRow(model: model, field: .keepalive(peerID)) {
                        MacEditField(title: MacStrings.keepalive, text: peer.keepalive, target: .keepalive(peerID))
                    }
                    MacCaptionedRow(model: model, field: .presharedKey(peerID)) {
                        MacKeyRow(
                            MacStrings.presharedKey, key: .presharedKey(peerID),
                            hasKey: peer.wrappedValue.presharedReference != nil, resetToken: model.keyResetRevision,
                            load: { model.presharedKeyForField(peerID: peerID) },
                            commit: { try model.setPresharedKey($0, peerID: peerID) },
                        )
                    }
                    HStack {
                        if peer.wrappedValue.presharedReference != nil {
                            Button(EditorStrings.clearPSK) { model.removePresharedKey(peerID: peerID) }
                                .wgexControl(.editor, "clearPSK", label: EditorStrings.clearPSK).lineLimit(1)
                        }
                        Spacer()
                        Button(MacStrings.removeServer, role: .destructive) { model.removePeer(id: peerID) }
                            .wgexControl(.editor, "removePeer", label: MacStrings.removeServer).lineLimit(1)
                            // The destructive look has no fill: its text ends on the field column's right edge.
                            .padding(.trailing, -MacFieldRowMetrics.unfilledButtonInset)
                    }
                }
            }
        }

        private var dnsServers: [String] {
            ProfileEditorModel.parts(model.draft.dns)
        }
    }

    /// IPv6 and DNS policy, as in the shared editor's Protection section (the iPhone and TV toggles do not apply).
    package struct MacTunnelProtectionSection: View {
        @Bindable package var model: ProfileEditorModel

        package var body: some View {
            Section(MacStrings.protection) {
                MacCaptionedRow(model: model, field: .ipv6Policy) {
                    ipv6Row
                }
                MacCaptionedRow(model: model, field: .dnsPolicy) {
                    dnsPolicyRow
                }
                if case .split = model.draft.protection.dnsPolicy {
                    MacFieldRow {
                        TextField(EditorStrings.splitDomains, text: splitDomains, prompt: MacEditField.prompt(EditorStrings.splitDomains))
                            .autocorrectionDisabled().lineLimit(1)
                            .wgexControl(.editor, "splitDomains", label: EditorStrings.splitDomains)
                    } label: {
                        Text(EditorStrings.splitDomains).lineLimit(1)
                    }
                }
            }
        }

        private var ipv6Row: some View {
            MacControlRow {
                Picker(EditorStrings.ipv6, selection: $model.draft.protection.ipv6Policy) {
                    Text(EditorStrings.tunnelIPv6).tag(IPv6Policy.tunnel)
                    Text(EditorStrings.blockIPv6).tag(IPv6Policy.blockOutside)
                    Text(EditorStrings.allowIPv6).tag(IPv6Policy.allowOutside)
                }.labelsHidden().fixedSize().wgexControl(.editor, "ipv6", label: EditorStrings.ipv6)
            } label: {
                Text(EditorStrings.ipv6).lineLimit(1)
            }
        }

        private var dnsPolicyRow: some View {
            MacControlRow {
                Picker(EditorStrings.dnsPolicy, selection: dnsSelection) {
                    Text(EditorStrings.tunnelDNS).tag(0)
                    Text(EditorStrings.splitDNS).tag(1)
                    Text(EditorStrings.systemDNS).tag(2)
                }.labelsHidden().fixedSize().wgexControl(.editor, "dnsPolicy", label: EditorStrings.dnsPolicy)
            } label: {
                Text(EditorStrings.dnsPolicy).lineLimit(1)
            }
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
    }

    /// A row of the Edit sheet with the model's messages about its field as captions under it: errors in the error colour,
    /// then warnings in caution, in the words of the problem list.
    package struct MacCaptionedRow<Row: View>: View {
        private let model: ProfileEditorModel
        private let field: EditorField
        private let row: Row

        package init(model: ProfileEditorModel, field: EditorField, @ViewBuilder row: () -> Row) {
            self.model = model
            self.field = field
            self.row = row()
        }

        /// One structure whether or not there are captions: a branch on the captions would give the row a new identity when
        /// its first caption comes or its last one goes, and the field being typed in would lose the focus (M07-T16).
        package var body: some View {
            let captions = MacFieldCaptions.lines(model.diagnostics(for: field), nameIsEmpty: model.draft.name.isEmpty)
            VStack(alignment: .leading, spacing: 3) {
                row
                ForEach(captions, id: \.self) { caption in
                    MacRowCaption(caption.text, tone: caption.isWarning ? .caution : .error)
                }
            }
        }
    }

    /// The captions of one row, and which fields have a row that shows them.
    package enum MacFieldCaptions {
        package struct Line: Hashable {
            package let text: String
            package let isWarning: Bool
        }

        /// One line per distinct message, errors first.
        package static func lines(_ issues: [ConfigDiagnostic], nameIsEmpty: Bool) -> [Line] {
            var seen = Set<String>()
            let ordered = issues.filter { $0.severity == .error } + issues.filter { $0.severity == .warning }
            return ordered.map { Line(text: MacTunnelProblems.text($0, nameIsEmpty: nameIsEmpty), isWarning: $0.severity == .warning) }
                .filter { seen.insert($0.text).inserted }
        }

        /// Whether the form shows this field's messages under its row (the on-demand group shows its own); the rest stay in
        /// the list under the form.
        package static func isShownAtRow(_ field: EditorField) -> Bool {
            switch field {
            case .summary, .peers, .transport, .exclusions: false
            case .name, .privateKey, .addresses, .listenPort, .mtu, .dns, .searchDomains, .ipv6Policy, .dnsPolicy, .onDemand,
                 .publicKey, .presharedKey, .endpoint, .allowedIPs, .keepalive: true
            }
        }
    }

    /// A labelled single-line text row of the Edit sheet; its problems are captions under the row (``MacCaptionedRow``).
    /// A key field is wide enough for a whole key.
    package struct MacEditField: View {
        package let title: String
        @Binding package var text: String
        package let target: EditorField
        package var monospaced = false

        package var body: some View {
            MacFieldRow(fieldWidth: monospaced ? MacFieldRowMetrics.keyWidth : MacFieldRowMetrics.fieldWidth) {
                TextField(title, text: $text, prompt: Self.prompt(title)).autocorrectionDisabled().lineLimit(1)
                    .font(monospaced ? MacDesign.body.monospaced() : MacDesign.body)
                    .wgexControl(.editor, "field", label: title, item: target.automationKey)
            } label: {
                Text(title).lineLimit(1)
            }
        }

        /// The field's own title as its placeholder, in textSecondary.
        package static func prompt(_ title: String) -> Text {
            Text(title).foregroundStyle(MacDesign.textSecondary)
        }
    }

    /// A switch row of the Edit sheet: the title on the left, the switch on the right; the toggle keeps its label and
    /// identifier.
    package struct MacSwitchRow<Control: View>: View {
        private let title: String
        private let control: Control

        package init(_ title: String, @ViewBuilder control: () -> Control) {
            self.title = title
            self.control = control()
        }

        package var body: some View {
            MacControlRow {
                control.toggleStyle(.switch).labelsHidden()
            } label: {
                Text(title).lineLimit(1)
            }
        }
    }

    /// Allowed IPs as one comma-separated line. The field keeps what is typed (a trailing comma included) while the model
    /// takes the parsed list; a change made elsewhere (Exclude private networks, a DNS edit) refreshes the field.
    package struct MacAllowedIPsField: View {
        @Binding package var model: AllowedIPsModel
        package let target: EditorField
        @State private var text = ""

        package var body: some View {
            MacFieldRow {
                TextField(MacStrings.allowedIPs, text: $text, prompt: MacEditField.prompt(MacStrings.allowedIPs))
                    .autocorrectionDisabled().lineLimit(1)
                    .wgexControl(.editor, "field", label: MacStrings.allowedIPs, item: target.automationKey)
            } label: {
                Text(MacStrings.allowedIPs).lineLimit(1)
            }
            .onAppear { text = model.text }
            .onChange(of: text) {
                let parsed = AllowedIPsModel(text: text)
                if parsed.texts != model.texts {
                    model = parsed
                }
            }
            .onChange(of: model) {
                if AllowedIPsModel(text: text).texts != model.texts {
                    text = model.text
                }
            }
        }
    }
#endif
