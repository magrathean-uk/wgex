// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Editor-side shape of a macOS on-demand policy (ADR-030 section 2): the official app's Ethernet and Wi-Fi checkboxes, the
/// network match and its list. The form writes only `.off` or `.interfaces`; a policy the editor did not change is kept as stored.
public struct MacOnDemandForm: Hashable, Sendable {
    /// The official SSID option: any network, only the listed ones, or every one except them.
    public enum NetworkMatch: Hashable, Sendable, CaseIterable {
        case any, only, except
    }

    /// One listed network name. Identity is stable while the row is edited; equality is by name.
    public struct Network: Identifiable, Hashable, Sendable {
        public let id: UUID
        public var name: String

        public init(id: UUID = UUID(), name: String) {
            self.id = id; self.name = name
        }

        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.name == rhs.name
        }

        public func hash(into hasher: inout Hasher) {
            hasher.combine(name)
        }
    }

    /// A list problem the editor reports before the daemon can refuse it (ADR-030 section 2 bounds).
    public enum Issue: Hashable, Sendable {
        case nameLength, nameControl, duplicate, listLimit

        /// Fixed copy for the issue.
        public var message: String {
            switch self {
            case .nameLength: MacStrings.onDemandNameLength
            case .nameControl: MacStrings.onDemandNameControl
            case .duplicate: MacStrings.onDemandNameDuplicate
            case .listLimit: MacStrings.onDemandListLimit
            }
        }
    }

    /// Outcome of adding a name to the list.
    public enum AddOutcome: Hashable, Sendable {
        case added, alreadyListed, listFull
    }

    /// The SSID list bound of ADR-030.
    public static let maximumNetworks = 64

    public var ethernet: Bool
    public var wifi: Bool
    public var match: NetworkMatch
    public var networks: [Network]

    public init(ethernet: Bool = false, wifi: Bool = false, match: NetworkMatch = .any, networks: [Network] = []) {
        self.ethernet = ethernet; self.wifi = wifi; self.match = match; self.networks = networks
    }

    /// Reads a stored policy. The legacy iOS shapes normalise as on the daemon: `.always` is Wi-Fi or Ethernet,
    /// `.wifiOnly` is Wi-Fi, an exception list becomes an exclude list, and `.cellularOnly` and `.iosInterfaces` have
    /// no macOS rule.
    public init(policy: OnDemandPolicy) {
        switch policy {
        case .off, .cellularOnly, .iosInterfaces:
            self.init()
        case let .always(exceptSSIDs):
            self.init(ethernet: true, wifi: true, matchList: exceptSSIDs.isEmpty ? .anySSID : .exceptSSIDs(exceptSSIDs))
        case let .wifiOnly(exceptSSIDs):
            self.init(ethernet: false, wifi: true, matchList: exceptSSIDs.isEmpty ? .anySSID : .exceptSSIDs(exceptSSIDs))
        case let .interfaces(interfaces):
            switch interfaces {
            case .ethernetOnly: self.init(ethernet: true, wifi: false, matchList: .anySSID)
            case let .wifiOnly(match): self.init(ethernet: false, wifi: true, matchList: match)
            case let .wifiOrEthernet(match): self.init(ethernet: true, wifi: true, matchList: match)
            }
        }
    }

    private init(ethernet: Bool, wifi: Bool, matchList: OnDemandSSIDMatch) {
        let match: NetworkMatch
        let names: [String]
        switch matchList {
        case .anySSID: match = .any; names = []
        case let .onlySSIDs(list): match = .only; names = list
        case let .exceptSSIDs(list): match = .except; names = list
        }
        self.init(ethernet: ethernet, wifi: wifi, match: match, networks: names.map { Network(name: $0) })
    }

    /// On-demand is on when at least one network type is selected.
    public var isEnabled: Bool {
        ethernet || wifi
    }

    /// True when the list is part of the result: Wi-Fi is selected and the match is not "any".
    public var usesList: Bool {
        wifi && match != .any
    }

    /// True when the list is empty: ADR-030 and the official app save an include or exclude rule with no network as
    /// "any network", and the editor says so before saving.
    public var savesAsAnyNetwork: Bool {
        usesList && networks.isEmpty
    }

    /// Problems with the list; empty when the form can be saved. An empty list is not a problem, see ``savesAsAnyNetwork``.
    public var issues: [Issue] {
        guard usesList else { return [] }
        var result: [Issue] = []
        if networks.count > Self.maximumNetworks {
            result.append(.listLimit)
        }
        if networks.contains(where: { !(1 ... 32).contains($0.name.utf8.count) }) {
            result.append(.nameLength)
        }
        if networks.contains(where: { Self.hasControl($0.name) }) {
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
        guard isEnabled else { return OnDemandPolicy.off }
        let names = networks.map(\.name)
        let ssidMatch: OnDemandSSIDMatch = switch (wifi, match) {
        case (false, _), (_, .any): .anySSID
        case (true, _) where names.isEmpty: .anySSID
        case (true, .only): .onlySSIDs(names)
        case (true, .except): .exceptSSIDs(names)
        }
        if wifi {
            return .interfaces(ethernet ? .wifiOrEthernet(ssidMatch) : .wifiOnly(ssidMatch))
        }
        return .interfaces(.ethernetOnly)
    }

    /// Appends a network name unless it is listed or the list is full; the editor shows the problems of an empty or odd name.
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

    /// The saved policy to write: the stored one while the form is unchanged, so a legacy shape is not rewritten by opening
    /// the editor, otherwise the form's own policy, falling back to the stored one while the list has a problem.
    public func resolved(against stored: OnDemandPolicy) -> OnDemandPolicy {
        if self == MacOnDemandForm(policy: stored) {
            return stored
        }
        return policy ?? stored
    }

    private static func hasControl(_ text: String) -> Bool {
        text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

/// What the app read from the connected Wi-Fi network for "Add connected network".
public enum ConnectedNetworkReading: Sendable, Equatable {
    case ssid(String)
    case notAssociated
    case notAuthorised
    case unreadable
}
