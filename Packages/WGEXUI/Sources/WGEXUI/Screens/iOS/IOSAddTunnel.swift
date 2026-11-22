// SPDX-License-Identifier: MIT

#if os(iOS)
    import SwiftUI
    import UniformTypeIdentifiers
    import WGEXCore

    /// Where a tunnel comes from. `review` only presents a review that another route queued (Open In, the share sheet).
    public enum IOSImportSource: Sendable {
        case scan, files, paste, review
    }

    /// The Add a Tunnel sheet (SPEC 6.1 carried to iOS by SPEC 10): Scan QR Code…, Import from File… (.conf or .zip),
    /// Paste Configuration… and Create Empty Tunnel. Every source ends in Review Tunnel; a zip with several tunnels ends
    /// in Review Tunnels, the ticked list. Open In and the share sheet arrive here as a queued review.
    public struct IOSAddTunnelSheet<Model: IOSAppState>: View {
        private enum Step: Hashable {
            case scan, paste
        }

        private let model: Model
        private let onDone: () -> Void
        private let createEmpty: () -> Void
        @State private var path: [Step]
        @State private var picking: Bool
        @State private var selection = MacImportSelection()

        /// `createEmpty` closes the sheet and opens the editor for a new tunnel.
        public init(
            model: Model,
            initialSource: IOSImportSource = .review,
            createEmpty: @escaping () -> Void,
            onDone: @escaping () -> Void,
        ) {
            self.model = model; self.onDone = onDone; self.createEmpty = createEmpty
            let first: [Step] = switch initialSource {
            case .scan: [.scan]
            case .paste: [.paste]
            case .files, .review: []
            }
            _path = State(initialValue: first)
            _picking = State(initialValue: initialSource == .files)
        }

        private var fileTypes: [UTType] {
            [UTType("com.wireguard.config"), .zip, .plainText].compactMap(\.self)
        }

        public var body: some View {
            NavigationStack(path: $path) {
                root
                    .navigationDestination(for: Step.self) { step in
                        switch step {
                        case .scan: IOSScanPage(model: model) { path = [] }
                        case .paste: IOSPastePage(model: model) { path = [] }
                        }
                    }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: fileTypes) { result in
                if case let .success(url) = result {
                    model.importFile(at: url)
                }
            }
            // A review replaces whatever source page is showing.
            .onChange(of: model.review == nil) { _, empty in
                if !empty {
                    path = []
                }
            }
            .onChange(of: model.profiles.count) { old, new in
                if new > old, model.review == nil {
                    onDone()
                }
            }
            .interactiveDismissDisabled(model.isBusy)
        }

        @ViewBuilder private var root: some View {
            if let review = model.review {
                if model.pendingReviewCount > 1 {
                    reviewList
                } else {
                    singleReview(review)
                }
            } else {
                sources
            }
        }

        // MARK: Sources

        private var sources: some View {
            Form {
                Section {
                    Button(PlatformStrings.scanQRCode, systemImage: "qrcode.viewfinder") { path = [.scan] }
                        .accessibilityIdentifier("wgex.importScan")
                    Button(MacStrings.importFromFile, systemImage: "doc.badge.plus") { picking = true }
                        .accessibilityIdentifier("wgex.chooseFile")
                    Button(PlatformStrings.pasteConfiguration, systemImage: "doc.on.clipboard") { path = [.paste] }
                        .accessibilityIdentifier("wgex.importPaste")
                    Button(MacStrings.createEmptyTunnel, systemImage: "square.and.pencil", action: createEmpty)
                        .accessibilityIdentifier("wgex.createEmpty")
                } header: {
                    Text(PlatformStrings.addATunnelMessageIOS).textCase(nil)
                }
                .accessibilityIdentifier("wgex.importSources")
                if let message = model.operationMessage {
                    Section { Text(message) }
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.addATunnelTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(MacStrings.cancel, action: cancel) } }
        }

        // MARK: Review Tunnel

        private func singleReview(_ review: ImportReviewModel) -> some View {
            ImportReviewScreen(model: review, onImport: { profile, secrets in
                try model.importReviewed(profile, secrets: secrets, connect: false)
            }, onImportAndConnect: { profile, secrets in
                try model.importReviewed(profile, secrets: secrets, connect: true)
            }, labels: ImportReviewLabels(
                title: MacStrings.reviewTunnelTitle, add: MacStrings.add, addAndActivate: MacStrings.addAndActivate,
            ))
            .id(ObjectIdentifier(review))
            .formStyle(.iosCards)
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .top, spacing: 0) {
                if review.profile.protection.ipv6Policy == .blockOutside {
                    Text(PlatformStrings.ipv6BlockedOutsideTunnel)
                        .font(IOSDesign.footer).foregroundStyle(IOSDesign.textSecondary)
                        .padding(IOSDesign.Space.page).frame(maxWidth: .infinity, alignment: .leading)
                        .background(IOSDesign.pageBackground)
                }
            }
            .disabled(model.isBusy)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(MacStrings.cancel, action: cancel) } }
        }

        // MARK: Review Tunnels (M07-T09's ticked list)

        private var reviewList: some View {
            let reviews = model.pendingReviews
            let ticked = selection.ticked(in: reviews)
            let leftOut = reviews.filter { !$0.canImport }.map(\.name)
            let addTitle = selection.buttonTitle(in: reviews)
            return Form {
                Section {
                    ForEach(Array(reviews.enumerated()), id: \.offset) { index, review in
                        Toggle(isOn: Binding(
                            get: { selection.isTicked(review) },
                            set: { selection.set(review, ticked: $0) },
                        )) {
                            Text(review.name).lineLimit(1).truncationMode(.middle)
                            Text(review.canImport ? MacImportSelection.endpoint(review) : review.errors.first?.message ?? MacStrings
                                .unavailable)
                                .lineLimit(2)
                        }
                        .toggleStyle(IOSTickStyle())
                        .disabled(!review.canImport)
                        .accessibilityIdentifier("wgex.importReview.item.\(index)")
                    }
                } footer: {
                    if !leftOut.isEmpty {
                        Text(MacStrings.leftOutWithErrors(leftOut.joined(separator: ", ")))
                    }
                }
                if let message = model.operationMessage {
                    Section { Text(message) }
                }
            }
            .formStyle(.iosCards)
            .navigationTitle(MacStrings.reviewTunnelsTitle)
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                IOSSheetActionBar {
                    Button { Task { await add(ticked) } } label: { Text(addTitle).frame(maxWidth: .infinity) }
                        .buttonStyle(.iosPrimary)
                        .disabled(ticked.isEmpty || model.isBusy)
                        .accessibilityIdentifier("wgex.importReview.addAll")
                }
            }
            .disabled(model.isBusy)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(MacStrings.cancel, action: cancel) } }
            .onChange(of: reviews.map(ObjectIdentifier.init)) { selection.prune(to: model.pendingReviews) }
        }

        /// Saves the ticked reviews in list order and drops the unticked ones, through the queue's own confirm and skip,
        /// so every save takes the single review's path. A save that fails stops here and leaves its review showing.
        private func add(_ ticked: [ImportReviewModel]) async {
            while let review = model.review {
                if ticked.contains(where: { $0 === review }) {
                    let before = model.pendingReviewCount
                    await model.confirmImport()
                    if model.pendingReviewCount == before {
                        return
                    }
                } else {
                    model.skipReview()
                }
            }
        }

        private func cancel() {
            model.cancelImport()
            onDone()
        }
    }

    /// A sheet page's default action as a full-width primary button, pinned under the cards on the page background.
    private struct IOSSheetActionBar<Content: View>: View {
        @ViewBuilder let content: Content

        var body: some View {
            content
                .padding(.horizontal, IOSDesign.Space.page).padding(.vertical, IOSDesign.Space.groupGap)
                .frame(maxWidth: .infinity)
                .background(IOSDesign.pageBackground)
        }
    }

    /// A tick at the leading edge, as in a system selection list; a review with errors shows none.
    private struct IOSTickStyle: ToggleStyle {
        @Environment(\.isEnabled) private var isEnabled

        func makeBody(configuration: Configuration) -> some View {
            Button { configuration.isOn.toggle() } label: {
                HStack(spacing: IOSDesign.Space.medium) {
                    Image(systemName: configuration.isOn ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(configuration.isOn ? IOSDesign.accent : IOSDesign.label3)
                        .opacity(isEnabled ? 1 : 0)
                        .accessibilityHidden(true)
                    IOSRowLabel { configuration.label }
                    Spacer(minLength: 0)
                }
                // The whole card row, padding included, ticks.
                .frame(minHeight: IOSDesignScale.minimumTouchHeight - 2 * IOSDesign.Space.rowVertical)
                .iosRowHitArea()
            }
            .buttonStyle(.plain)
            .accessibilityAddTraits(configuration.isOn ? .isSelected : [])
        }
    }

    /// The camera for a WireGuard QR code. A payload or a failure returns to the sheet's first page or its review.
    private struct IOSScanPage<Model: IOSAppState>: View {
        let model: Model
        let back: () -> Void

        var body: some View {
            IOSQRScannerView(onPayload: { payload in
                model.prepareScannedCode(payload)
                back()
            }, onFailure: { failure in
                model.reportScanFailure(failure)
                back()
            })
            .ignoresSafeArea(edges: .bottom)
            .accessibilityIdentifier("wgex.qrScanner")
            .navigationTitle(PlatformStrings.scanQRCode)
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    /// A pasted configuration. The text is cleared when the page closes or the app leaves the foreground.
    private struct IOSPastePage<Model: IOSAppState>: View {
        let model: Model
        let back: () -> Void
        @State private var text = ""
        @FocusState private var focused: Bool
        @Environment(\.scenePhase) private var scenePhase

        var body: some View {
            Form {
                Section {
                    TextEditor(text: $text)
                        .focused($focused)
                        .frame(minHeight: 180)
                        .scrollContentBackground(.hidden)
                        .font(IOSDesign.body.monospaced())
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                        .privacySensitive().accessibilityIdentifier("wgex.pasteConfiguration")
                }
            }
            .formStyle(.iosCards)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                IOSSheetActionBar {
                    Button {
                        focused = false
                        model.prepareImport(text)
                        text = ""
                        if model.review == nil {
                            back()
                        }
                    } label: {
                        Text(PlatformStrings.reviewConfiguration).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.iosPrimary)
                    .disabled(text.isEmpty)
                    .accessibilityIdentifier("wgex.reviewConfiguration")
                }
            }
            .navigationTitle(PlatformStrings.pasteConfiguration)
            .navigationBarTitleDisplayMode(.inline)
            .scrollDismissesKeyboard(.interactively)
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button(MacStrings.done) { focused = false }.accessibilityIdentifier("wgex.pasteDone")
                }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase != .active {
                    text = ""
                }
            }
            .onDisappear { text = "" }
        }
    }
#endif
