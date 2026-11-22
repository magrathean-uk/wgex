// SPDX-License-Identifier: MIT

#if os(macOS)
    import SwiftUI
    import WGEXCore

    /// Plain-word problem lines for the Mac sheets (SPEC 6.2 and 6.3). A diagnostic with its own message keeps it; the
    /// generic Core copy, which is shared with other platforms, is reworded in SPEC 3 words where it matters on the Mac.
    package enum MacTunnelProblems {
        package static func text(_ issue: ConfigDiagnostic, nameIsEmpty: Bool = false) -> String {
            guard issue.message == UserStrings.diagnostic(issue.code) else { return issue.message }
            switch issue.code {
            case .ignoredHook: return MacStrings.commandsWereRemoved
            case .unsupportedSetting: return MacStrings.settingWasRemoved
            case .duplicatePeer: return MacStrings.serversShareAKey
            case .keyInUseElsewhere: return MacStrings.keyUsedByAnotherTunnel
            case .noAddresses: return MacStrings.needsAnAddress
            case .noPeers: return MacStrings.needsAServer
            case .limitExceeded where nameIsEmpty: return MacStrings.typeATunnelName
            default: return issue.message
            }
        }

        /// One line per distinct problem, errors first.
        package static func lines(_ issues: [ConfigDiagnostic], nameIsEmpty: Bool = false) -> [String] {
            var seen = Set<String>()
            let ordered = issues.filter { $0.severity == .error } + issues.filter { $0.severity == .warning }
            return ordered.map { text($0, nameIsEmpty: nameIsEmpty) }.filter { seen.insert($0).inserted }
        }

        /// SPEC 6.2: "All traffic" for 0.0.0.0/0, with or without ::/0; otherwise the list.
        package static func routes(_ profile: TunnelProfile) -> String {
            let ranges = profile.peers.flatMap(\.allowedIPs).map(\.stringRepresentation)
            guard !ranges.isEmpty else { return MacStrings.unavailable }
            let rest = Set(ranges).subtracting(["0.0.0.0/0", "::/0"])
            return ranges.contains("0.0.0.0/0") && rest.isEmpty ? MacStrings.allTraffic : ranges.joined(separator: ", ")
        }
    }

    /// The Add a Tunnel sheet, and after any import the Review Tunnel sheet (SPEC 6.1 and 6.2). Secrets remain in the review
    /// owner's wiped buffers and are borrowed only at confirmation.
    public struct MacImportSheet: View {
        private let reviews: [ImportReviewModel]
        private let chooseFile: () -> Void
        private let paste: () -> Void
        private let createEmpty: () -> Void
        private let cancel: () -> Void
        private let dropProfiles: ([URL]) -> Bool
        private let saving: Bool
        private let errorMessage: String?
        private let confirm: (TunnelProfile, borrowing ParsedSecrets, Bool, UUID?) throws -> Void
        private let confirmAll: ([ImportReviewModel]) -> Void
        @State private var replace = false
        @State private var selection = MacImportSelection()

        /// No review shows Add a Tunnel; one review shows Review Tunnel; several show the ticked list, whose Add button passes
        /// the ticked reviews to `confirmAll`. Saving prevents dismissal and duplicate actions.
        public init(
            review: ImportReviewModel? = nil,
            reviews: [ImportReviewModel] = [],
            chooseFile: @escaping () -> Void = {},
            paste: @escaping () -> Void = {},
            createEmpty: @escaping () -> Void = {},
            cancel: @escaping () -> Void = {},
            dropProfiles: @escaping ([URL]) -> Bool = { _ in false },
            saving: Bool = false,
            errorMessage: String? = nil,
            confirm: @escaping (TunnelProfile, borrowing ParsedSecrets, Bool, UUID?) throws -> Void = { _, _, _, _ in },
            confirmAll: @escaping ([ImportReviewModel]) -> Void = { _ in },
        ) {
            self.reviews = reviews.isEmpty ? review.map { [$0] } ?? [] : reviews
            self.chooseFile = chooseFile; self.paste = paste; self.createEmpty = createEmpty; self.cancel = cancel
            self.dropProfiles = dropProfiles; self.saving = saving; self.errorMessage = errorMessage
            self.confirm = confirm; self.confirmAll = confirmAll
        }

        public var body: some View {
            Group {
                if reviews.count > 1 {
                    listContent
                } else if let review = reviews.first {
                    reviewContent(review)
                } else {
                    MacAddTunnelView(
                        chooseFile: chooseFile, paste: paste, createEmpty: createEmpty, dismiss: cancel, message: errorMessage,
                    )
                }
            }
            .disabled(saving)
            .interactiveDismissDisabled(saving)
            .dropDestination(for: URL.self) { urls, _ in
                guard !urls.isEmpty else { return false }
                return dropProfiles(urls)
            }
            .buttonStyle(.macSecondary)
            .padding(20).frame(width: 520).background(MacDesign.pageBackground)
            .accessibilityElement(children: .contain)
            .wgexAX(.importReview, "surface", label: title)
        }

        private var title: String {
            reviews.count > 1 ? MacStrings.reviewTunnelsTitle : reviews.isEmpty ? MacStrings.addATunnelTitle : MacStrings.reviewTunnelTitle
        }

        // MARK: One configuration

        private func reviewContent(_ review: ImportReviewModel) -> some View {
            @Bindable var review = review
            return VStack(alignment: .leading, spacing: 14) {
                Text(MacStrings.reviewTunnelTitle).font(MacDesign.heading).lineLimit(1)
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        VStack(spacing: 0) {
                            MacSheetRow(MacStrings.name) {
                                TextField(MacStrings.name, text: $review.name).labelsHidden().multilineTextAlignment(.trailing)
                                    .textFieldStyle(.plain).lineLimit(1)
                                    .wgexControl(.importReview, "name", label: MacStrings.name)
                            }
                            Divider().padding(.leading, 12)
                            valueRow(MacStrings.server, value: server(review.profile))
                                .wgexAX(.importReview, "endpoint", label: MacStrings.server)
                            Divider().padding(.leading, 12)
                            valueRow(MacStrings.tunnelAddress, value: addresses(review.profile))
                                .wgexAX(.importReview, "addresses", label: MacStrings.tunnelAddress)
                            Divider().padding(.leading, 12)
                            valueRow(MacStrings.routes, value: MacTunnelProblems.routes(review.profile))
                                .wgexAX(.importReview, "routes", label: MacStrings.routes)
                        }.macCard(padding: 0)
                        if review.showsIPv6PolicyChoice {
                            ImportIPv6PolicyPicker(model: review).padding(12).macCard(padding: 0)
                        }
                        if review.replacementCandidate != nil {
                            duplicateChoice(review)
                        }
                        problems(MacTunnelProblems.lines(review.diagnostics, nameIsEmpty: review.name.isEmpty))
                        if review.actionFailed {
                            Text(MacStrings.importCouldNotBeCompletedTry).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        }
                    }
                }.frame(maxHeight: 420).fixedSize(horizontal: false, vertical: true)
                if let errorMessage {
                    Text(errorMessage).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        .fixedSize(horizontal: false, vertical: true)
                        .wgexAX(.importReview, "errorMessage", label: errorMessage)
                }
                HStack {
                    cancelButton
                    Spacer()
                    Button(MacStrings.add) { accept(review, activate: false) }
                        .wgexControl(.importReview, "importLabel", label: MacStrings.add)
                        .disabled(!review.canImport).lineLimit(1)
                    Button(MacStrings.addAndActivate) { accept(review, activate: true) }
                        .wgexControl(.importReview, "importAndConnect", label: MacStrings.addAndActivate)
                        .buttonStyle(.macPrimary).disabled(!review.canImport).keyboardShortcut(.defaultAction).lineLimit(1)
                }
            }
        }

        private func duplicateChoice(_ review: ImportReviewModel) -> some View {
            VStack(alignment: .leading, spacing: 8) {
                Text(MacStrings.matchingTunnelExists).font(.body.weight(.semibold))
                Text(MacStrings.keepBothOrReplaceTunnel).font(MacDesign.note).foregroundStyle(MacDesign.label2)
                    .fixedSize(horizontal: false, vertical: true)
                Picker(MacStrings.duplicate, selection: $replace) {
                    Text(MacStrings.keepBoth).tag(false); Text(MacStrings.replace).tag(true)
                }.wgexControl(.importReview, "duplicate", label: MacStrings.duplicate).pickerStyle(.segmented).labelsHidden()
                    .onChange(of: replace) { _, now in review.setReplacing(now) }
                if review.keyInUseElsewhere {
                    Text(MacStrings.usingTheSamePrivateKeyOnTwo).font(MacDesign.note).fixedSize(horizontal: false, vertical: true)
                }
            }.padding(12).macCard(padding: 0)
        }

        // MARK: Several configurations

        private var listContent: some View {
            let leftOut = reviews.filter { !$0.canImport }.map(\.name)
            let ticked = selection.ticked(in: reviews)
            let addTitle = selection.buttonTitle(in: reviews)
            return VStack(alignment: .leading, spacing: 14) {
                Text(MacStrings.reviewTunnelsTitle).font(MacDesign.heading).lineLimit(1)
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(reviews.enumerated()), id: \.offset) { index, review in
                            if index > 0 {
                                Divider().padding(.leading, 12)
                            }
                            listRow(review, index: index)
                        }
                    }.macCard(padding: 0)
                }.frame(maxHeight: 360).fixedSize(horizontal: false, vertical: true)
                if !leftOut.isEmpty {
                    Text(MacStrings.leftOutWithErrors(leftOut.joined(separator: ", "))).font(MacDesign.small)
                        .foregroundStyle(MacDesign.label2).fixedSize(horizontal: false, vertical: true)
                }
                if let errorMessage {
                    Text(errorMessage).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        .fixedSize(horizontal: false, vertical: true)
                        .wgexAX(.importReview, "errorMessage", label: errorMessage)
                }
                HStack {
                    cancelButton
                    Spacer()
                    Button(addTitle) { confirmAll(ticked) }
                        .wgexControl(.importReview, "addAll", label: addTitle)
                        .buttonStyle(.macPrimary).keyboardShortcut(.defaultAction).lineLimit(1)
                        .disabled(ticked.isEmpty)
                }
            }
            .onChange(of: reviews.map(ObjectIdentifier.init)) { selection.prune(to: reviews) }
        }

        /// One tunnel of the list: a tick (none for a tunnel with errors), the name, the server, and why it cannot be added.
        private func listRow(_ review: ImportReviewModel, index: Int) -> some View {
            let first = MacTunnelProblems.lines(review.diagnostics, nameIsEmpty: review.name.isEmpty).first
            let endpoint = MacImportSelection.endpoint(review)
            return HStack(alignment: .firstTextBaseline, spacing: 10) {
                Toggle(review.name, isOn: Binding(
                    get: { selection.isTicked(review) },
                    set: { selection.set(review, ticked: $0) },
                ))
                .toggleStyle(.checkbox).labelsHidden().disabled(!review.canImport)
                .wgexControl(.importReview, "itemTick", label: review.name, item: String(index))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 12) {
                        Text(review.name).lineLimit(1).truncationMode(.middle).layoutPriority(1)
                        Spacer(minLength: 12)
                        Text(endpoint).lineLimit(1).truncationMode(.middle).foregroundStyle(MacDesign.label2)
                            .wgexAX(.importReview, "itemEndpoint", label: endpoint, item: String(index))
                    }
                    Text(first ?? MacStrings.readyToAdd).font(MacDesign.small).foregroundStyle(MacDesign.label2)
                        .lineLimit(2)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .combine)
                // The combined row's label is the name alone, so the server is its value, as on the one-tunnel review's rows.
                .accessibilityValue(endpoint)
                .wgexAX(.importReview, "item", label: review.name, item: String(index))
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
        }

        // MARK: Parts

        private var cancelButton: some View {
            Button(MacStrings.cancel, action: cancel).wgexControl(.importReview, "cancel", label: MacStrings.cancel)
                .keyboardShortcut(.cancelAction).lineLimit(1)
        }

        @ViewBuilder private func problems(_ lines: [String]) -> some View {
            if !lines.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(lines, id: \.self) { line in
                        Text(line).font(MacDesign.small).foregroundStyle(MacDesign.label2).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .combine)
                .wgexAX(.importReview, "problems", label: lines.joined(separator: " "))
            }
        }

        private func valueRow(_ title: String, value: String) -> some View {
            MacSheetRow(title) {
                Text(value).lineLimit(1).truncationMode(.middle).foregroundStyle(MacDesign.label2).textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue(value)
        }

        private func server(_ profile: TunnelProfile) -> String {
            profile.peers.first?.endpoint.map(EndpointText.format) ?? MacStrings.unavailable
        }

        private func addresses(_ profile: TunnelProfile) -> String {
            let text = profile.interface.addresses.map(\.stringRepresentation).joined(separator: ", ")
            return text.isEmpty ? MacStrings.unavailable : text
        }

        private func accept(_ review: ImportReviewModel, activate: Bool) {
            let replacement = replace ? review.replacementCandidate : nil
            review.confirm { profile, secrets in
                var profile = profile
                if !replace {
                    profile.name = MacImportNaming.unique(profile.name, among: review.existingProfiles)
                }
                try confirm(profile, secrets, activate, replacement)
            }
        }
    }

    /// Keep Both: a name already in use gets a numbered suffix, as the review always did.
    public enum MacImportNaming {
        public static func unique(_ name: String, among profiles: [TunnelProfile]) -> String {
            let names = Set(profiles.map { $0.name.lowercased() })
            var candidate = name
            var suffix = 2
            while names.contains(candidate.lowercased()) {
                candidate = MacStrings.profileNameWithSuffix(String(name), String(suffix)); suffix += 1
            }
            return candidate
        }
    }

    /// One grouped-form row: a sentence-case label on the left, its value or control on the right, never wrapping.
    package struct MacSheetRow<Value: View>: View {
        private let title: String
        private let value: Value

        package init(_ title: String, @ViewBuilder value: () -> Value) {
            self.title = title; self.value = value()
        }

        package var body: some View {
            HStack(spacing: 12) {
                Text(title).lineLimit(1).layoutPriority(1)
                Spacer(minLength: 12)
                value
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
        }
    }
#endif
