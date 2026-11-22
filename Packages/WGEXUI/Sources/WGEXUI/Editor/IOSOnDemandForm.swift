// SPDX-License-Identifier: MIT
import Foundation
import SwiftUI
import WGEXCore

/// Editor-side shape of an iOS on-demand policy: the official iOS app's Cellular and Wi-Fi toggles, the SSID match and its
/// list. The form writes only `.off` or `.iosInterfaces`; a policy the editor did not change is kept as stored.
public struct IOSOnDemandForm: Hashable, Sendable {
    public typealias NetworkMatch = MacOnDemandForm.NetworkMatch
    public typealias Network = MacOnDemandForm.Network
    public typealias Issue = MacOnDemandForm.Issue
    public typealias AddOutcome = MacOnDemandForm.AddOutcome

    /// The same SSID list bound as the Mac editor.
    public static let maximumNetworks = MacOnDemandForm.maximumNetworks

    public var cellular: Bool
    public var wifi: Bool
    public var match: NetworkMatch
    public var networks: [Network]

    public init(cellular: Bool = false, wifi: Bool = false, match: NetworkMatch = .any, networks: [Network] = []) {
        self.cellular = cellular; self.wifi = wifi; self.match = match; self.networks = networks
    }

    /// Reads a stored policy as iOS evaluates it: `.always` is Wi-Fi and Cellular, `.wifiOnly` is Wi-Fi, an exception
    /// list is an exclude list, and the macOS option set has no iOS rule, so it reads as off.
    public init(policy: OnDemandPolicy) {
        switch policy {
        case .off, .interfaces:
            self.init()
        case .cellularOnly:
            self.init(cellular: true)
        case let .always(exceptSSIDs):
            self.init(cellular: true, wifi: true, matchList: exceptSSIDs.isEmpty ? .anySSID : .exceptSSIDs(exceptSSIDs))
        case let .wifiOnly(exceptSSIDs):
            self.init(cellular: false, wifi: true, matchList: exceptSSIDs.isEmpty ? .anySSID : .exceptSSIDs(exceptSSIDs))
        case let .iosInterfaces(interfaces):
            switch interfaces {
            case .cellularOnly: self.init(cellular: true)
            case let .wifiOnly(match): self.init(cellular: false, wifi: true, matchList: match)
            case let .wifiOrCellular(match): self.init(cellular: true, wifi: true, matchList: match)
            }
        }
    }

    private init(cellular: Bool, wifi: Bool, matchList: OnDemandSSIDMatch) {
        let match: NetworkMatch
        let names: [String]
        switch matchList {
        case .anySSID: match = .any; names = []
        case let .onlySSIDs(list): match = .only; names = list
        case let .exceptSSIDs(list): match = .except; names = list
        }
        self.init(cellular: cellular, wifi: wifi, match: match, networks: names.map { Network(name: $0) })
    }

    /// On-demand is on when Cellular or Wi-Fi is on.
    public var isEnabled: Bool {
        cellular || wifi
    }

    /// True when the list is part of the result: Wi-Fi is on and the match is not "any".
    public var usesList: Bool {
        wifi && match != .any
    }

    /// An include or exclude choice with no SSID saves as any SSID, as in the official app.
    public var savesAsAnySSID: Bool {
        usesList && networks.isEmpty
    }

    /// Problems with the list; empty when the form can be saved.
    public var issues: [Issue] {
        guard usesList else { return [] }
        var result: [Issue] = []
        if networks.count > Self.maximumNetworks {
            result.append(.listLimit)
        }
        if networks.contains(where: { !(1 ... 32).contains($0.name.utf8.count) }) {
            result.append(.nameLength)
        }
        if networks.contains(where: { $0.name.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) } }) {
            result.append(.nameControl)
        }
        if Set(networks.map(\.name)).count != networks.count {
            result.append(.duplicate)
        }
        return result
    }

    /// The policy this form writes, or nil while the list has a problem.
    public var policy: OnDemandPolicy? {
        guard issues.isEmpty else { return nil }
        guard isEnabled else { return .off }
        guard wifi else { return .iosInterfaces(.cellularOnly) }
        let names = networks.map(\.name)
        let ssidMatch: OnDemandSSIDMatch = switch match {
        case _ where names.isEmpty: .anySSID
        case .any: .anySSID
        case .only: .onlySSIDs(names)
        case .except: .exceptSSIDs(names)
        }
        return .iosInterfaces(cellular ? .wifiOrCellular(ssidMatch) : .wifiOnly(ssidMatch))
    }

    /// Appends a network name unless it is listed or the list is full.
    public mutating func add(_ name: String) -> AddOutcome {
        guard networks.count < Self.maximumNetworks else { return .listFull }
        guard !networks.contains(where: { $0.name == name }) else { return .alreadyListed }
        networks.append(Network(name: name))
        return .added
    }

    /// Appends an empty row for the user to type into.
    public mutating func addBlankRow() {
        guard networks.count < Self.maximumNetworks else { return }
        networks.append(Network(name: ""))
    }

    /// The policy to save: the stored one while the form is unchanged, so a legacy shape is not rewritten by opening the
    /// editor, otherwise the form's own policy, falling back to the stored one while the list has a problem.
    public func resolved(against stored: OnDemandPolicy) -> OnDemandPolicy {
        if self == IOSOnDemandForm(policy: stored) {
            return stored
        }
        return policy ?? stored
    }

    /// The detail's "On-demand" row, as the official iOS app words it.
    public var activationSummary: String {
        switch (cellular, wifi) {
        case (false, false): IOSOnDemandStrings.off
        case (true, false): IOSOnDemandStrings.cellularOnly
        case (false, true): IOSOnDemandStrings.wifiOnly
        case (true, true): IOSOnDemandStrings.wifiOrCellular
        }
    }

    /// The detail's "SSIDs" row; nil unless Wi-Fi is on.
    public var ssidSummary: String? {
        guard wifi else { return nil }
        let names = networks.map(\.name)
        return switch match {
        case _ where names.isEmpty: IOSOnDemandStrings.anySSID
        case .any: IOSOnDemandStrings.anySSID
        case .only: IOSOnDemandStrings.onlySSIDs + ": " + names.joined(separator: ", ")
        case .except: IOSOnDemandStrings.exceptSSIDs + ": " + names.joined(separator: ", ")
        }
    }
}

/// Copy of the iOS on-demand editor and the tunnel detail's summary.
public nonisolated enum IOSOnDemandStrings {
    public static let section = "On-demand activation"
    public static let cellular = "Cellular"
    public static let wifi = "Wi-Fi"
    public static let ssids = "SSIDs"
    public static let anySSID = "Any SSID"
    public static let onlySSIDs = "Only these SSIDs"
    public static let exceptSSIDs = "Except these SSIDs"
    public static let ssidName = "SSID"
    public static let addSSID = "Add SSID"
    public static let removeSSID = "Remove SSID"
    public static let addCurrent = "Add current network"
    public static let emptyListNote = "No SSID is listed, so this saves as Any SSID."
    public static let offNote = "Turn on Cellular, Wi-Fi or both to activate this tunnel on demand."
    public static let installNote = "Adding the current network needs this tunnel's VPN configuration installed. Save the tunnel first."
    public static let currentUnreadable =
        "The current network could not be read. Connect to Wi-Fi; iOS shares its name only while this tunnel's VPN configuration is installed."
    public static let currentAlreadyListed = "That network is already listed."
    public static let off = "Off"
    public static let cellularOnly = "Cellular only"
    public static let wifiOnly = "Wi-Fi only"
    public static let wifiOrCellular = "Wi-Fi or cellular"
    public static let detailRow = "On-demand"
}

#if os(iOS)
    /// The per-tunnel on-demand section of the official iOS app: Cellular, Wi-Fi, and any, included or excluded SSIDs.
    /// It edits the model only; the owner saves the profile and the system evaluates the rules.
    package struct IOSOnDemandSection: View {
        @Bindable package var model: ProfileEditorModel
        /// Reads the current SSID; nil while the tunnel's VPN configuration is not installed.
        package let connectedNetwork: (() async -> ConnectedNetworkReading)?
        @State private var listMessage: String?

        package var body: some View {
            Section {
                IOSListCardRows {
                    Toggle(IOSOnDemandStrings.cellular, isOn: $model.iosOnDemand.cellular)
                    Toggle(IOSOnDemandStrings.wifi, isOn: $model.iosOnDemand.wifi)
                        .wgexControl(.editor, "onDemandWiFi", label: IOSOnDemandStrings.wifi)
                    if !model.iosOnDemand.isEnabled {
                        IOSRowCaption(IOSOnDemandStrings.offNote)
                    }
                    if model.iosOnDemand.wifi {
                        // A pop-up row as the editor's other pickers: the value keeps its own width.
                        IOSControlRow {
                            Picker(IOSOnDemandStrings.ssids, selection: $model.iosOnDemand.match) {
                                Text(IOSOnDemandStrings.anySSID).tag(IOSOnDemandForm.NetworkMatch.any)
                                Text(IOSOnDemandStrings.onlySSIDs).tag(IOSOnDemandForm.NetworkMatch.only)
                                Text(IOSOnDemandStrings.exceptSSIDs).tag(IOSOnDemandForm.NetworkMatch.except)
                            }
                            .wgexControl(.editor, "onDemandNetworks", label: IOSOnDemandStrings.ssids)
                            .iosMenuPicker()
                        } label: {
                            Text(IOSOnDemandStrings.ssids)
                        }
                    }
                }
            } header: {
                IOSGroupHeading(IOSOnDemandStrings.section).iosGridHeader()
            }
            if model.iosOnDemand.wifi, model.iosOnDemand.usesList {
                listSection
            }
        }

        /// The SSID list as its own card, its rows set by hand so the ForEach keeps swipe to delete; Add SSID and Add
        /// current network as one action row under the names, a continuation of the last name as the editor's action rows
        /// are; the notes and the list's problems are captions under it, in the order they had.
        private var listSection: some View {
            let networks = model.iosOnDemand.networks
            let count = networks.count + 1
            return Section {
                ForEach($model.iosOnDemand.networks) { $network in
                    IOSFieldRow {
                        TextField(IOSOnDemandStrings.ssidName, text: $network.name, prompt: iosFieldPrompt(IOSOnDemandStrings.ssidName))
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .wgexControl(.editor, "onDemandNetwork", label: IOSOnDemandStrings.ssidName, item: network.id.uuidString)
                    } label: {
                        Text(IOSOnDemandStrings.ssidName)
                    }
                    .iosCardRow(IOSCardRowPosition(index: networks.firstIndex { $0.id == network.id } ?? 0, count: count))
                }
                .onDelete { offsets in
                    model.iosOnDemand.networks.remove(atOffsets: offsets); listMessage = nil
                }
                IOSActionRow {
                    Button(IOSOnDemandStrings.addSSID) {
                        model.iosOnDemand.addBlankRow(); listMessage = nil
                    }
                    .disabled(model.iosOnDemand.networks.count >= IOSOnDemandForm.maximumNetworks)
                    .wgexControl(.editor, "onDemandAddNetwork", label: IOSOnDemandStrings.addSSID)
                    Button(IOSOnDemandStrings.addCurrent) { Task { await addCurrent() } }
                        .disabled(connectedNetwork == nil || model.iosOnDemand.networks.count >= IOSOnDemandForm.maximumNetworks)
                        .wgexControl(.editor, "onDemandAddConnected", label: IOSOnDemandStrings.addCurrent)
                }
                .iosCardRow(IOSCardRowPosition(index: count - 1, count: count), kind: networks.isEmpty ? .row : .continuation)
            } footer: {
                listNotes.iosListHeader()
            }
        }

        private var listNotes: some View {
            VStack(alignment: .leading, spacing: IOSDesign.Space.micro) {
                if connectedNetwork == nil {
                    IOSRowCaption(IOSOnDemandStrings.installNote)
                }
                if model.iosOnDemand.savesAsAnySSID {
                    IOSRowCaption(IOSOnDemandStrings.emptyListNote, tone: .caution)
                }
                if let listMessage {
                    IOSRowCaption(listMessage, tone: .caution)
                }
                ForEach(model.iosOnDemandEdited ? model.iosOnDemand.issues : [], id: \.self) { issue in
                    IOSRowCaption(issue.message, tone: .error)
                }
            }
        }

        /// iOS shares the current SSID with an app whose VPN configuration is installed; no location prompt is shown.
        private func addCurrent() async {
            guard let connectedNetwork else { return }
            switch await connectedNetwork() {
            case let .ssid(name):
                switch model.iosOnDemand.add(name) {
                case .added: listMessage = nil
                case .alreadyListed: listMessage = IOSOnDemandStrings.currentAlreadyListed
                case .listFull: listMessage = MacStrings.onDemandListLimit
                }
            case .notAssociated, .notAuthorised, .unreadable:
                listMessage = IOSOnDemandStrings.currentUnreadable
            }
        }
    }
#endif
