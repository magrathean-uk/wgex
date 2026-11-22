// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public extension ProfileEditorModel {
    /// Live core diagnostics plus throwing-initialiser failures for unfinished text.
    var diagnostics: [EditorDiagnostic] {
        let revision = validationRevision
        if let cachedValidation, cachedValidation.revision == revision {
            return cachedValidation.diagnostics
        }
        var result = fieldDiagnostics
        let candidate = candidateProfile
        result += candidate.validate(publicKeysInUse: publicKeysInUse).map { issue in
            EditorDiagnostic(incompleteAllowed ? Self.allowingIncomplete(issue) : issue, fields: fields(for: issue))
        }
        if incompleteAllowed, !candidate.isComplete,
           candidate.macOptions != MacProfileOptions() || MacOnDemandForm(policy: candidate.onDemand).isEnabled
        {
            result.append(EditorDiagnostic(
                ConfigDiagnostic(severity: .error, code: .unsupportedSetting, message: MacStrings.incompleteTunnelOptions),
                fields: [.onDemand],
            ))
        }
        var seen = Set<EditorDiagnostic>()
        let unique = result.filter { seen.insert($0).inserted }
        cachedValidation = (revision, unique)
        return unique
    }

    /// DEC-088: the draft may be saved without an address or a server. Only a new tunnel or one saved incomplete qualifies;
    /// a saved complete tunnel cannot be saved back to incomplete.
    var incompleteAllowed: Bool {
        allowsIncomplete && !sourceProfile.isComplete
    }

    /// Whether any field holds text that does not parse (or a key is missing), so the draft cannot be written as a file.
    var hasFieldErrors: Bool {
        !fieldDiagnostics.isEmpty
    }

    func diagnostics(for field: EditorField) -> [ConfigDiagnostic] {
        diagnostics.filter { $0.fields.contains(field) }.map(\.diagnostic)
    }

    /// The editor uses Core's throwing parser for both the inline field and Save gating.
    static func endpointValidation(_ text: String) -> FieldValidation {
        guard !text.isEmpty else { return .empty }
        do { _ = try Endpoint(text); return .valid }
        catch { return .invalid(UserStrings.diagnostic(error == .invalidPort ? .invalidPort : .invalidEndpoint)) }
    }

    /// Complete mapping, including parser-only codes that may be shown by a host summary.
    static func defaultFields(for code: ConfigDiagnostic.Code) -> Set<EditorField> {
        diagnosticTargets[code] ?? [.summary]
    }

    private static let diagnosticTargets: [ConfigDiagnostic.Code: Set<EditorField>] = [
        .unknownKey: [.summary], .ignoredHook: [.summary], .amneziaField: [.summary], .duplicateKey: [.summary],
        .unsupportedSetting: [.summary], .invalidDNS: [.dns, .dnsPolicy], .invalidKeepalive: [.peers],
        .noAddresses: [.addresses], .invalidCIDR: [.addresses], .noPeers: [.peers], .duplicatePeer: [.peers],
        .carrierRequiresSinglePeer: [.peers], .invalidKey: [.privateKey], .keyInUseElsewhere: [.privateKey],
        .invalidPort: [.listenPort], .invalidMTU: [.mtu], .dnsOutsideAllowedIPs: [.dns, .dnsPolicy],
        .ipv6PolicyRequired: [.ipv6Policy], .limitExceeded: [.name, .addresses, .dns, .peers],
        .controlCharacter: [.name, .searchDomains, .dnsPolicy], .invalidEndpoint: [.peers, .transport],
        .keepaliveClampedByCarrier: [.peers, .transport], .exclusionPortEphemeral: [.exclusions],
    ]
}

extension ProfileEditorModel {
    package var candidateProfile: TunnelProfile {
        var result = sourceProfile
        result.name = draft.name
        result.interface = InterfaceConfiguration(
            addresses: Self.parts(draft.addresses).compactMap { try? IPAddressRange($0) },
            listenPort: UInt16(draft.listenPort), mtu: UInt16(draft.mtu),
            dns: Self.parts(draft.dns).compactMap { try? DNSServer($0) },
            searchDomains: Self.parts(draft.searchDomains), publicKey: publicKey,
        )
        result.peers = draft.peers.compactMap { peer in
            guard let key = try? PublicKey(base64: peer.publicKey) else { return nil }
            return PeerConfiguration(
                publicKey: key,
                hasPresharedKey: peer.presharedReference != nil,
                allowedIPs: peer.allowedIPs.texts
                    .compactMap { try? IPAddressRange($0.trimmingCharacters(in: .whitespaces)) },
                endpoint: try? Endpoint(peer.endpoint),
                persistentKeepalive: UInt16(peer.keepalive),
            )
        }
        result.secrets.presharedKeys = [:]
        for peer in draft.peers {
            if let ref = peer.presharedReference,
               let key = try? PublicKey(base64: peer.publicKey)
            {
                result.secrets.presharedKeys[key] = ref
            }
        }
        result.protection = draft.protection; result.onDemand = draft.resolvedOnDemand; result.macOptions = draft.macOptions
        result.exclusions = Self.exclusions(draft.exclusions)
        return result
    }

    /// A missing address or server stops activation, not saving: it stays listed, as a warning in plain words.
    private static func allowingIncomplete(_ issue: ConfigDiagnostic) -> ConfigDiagnostic {
        switch issue.code {
        case .noAddresses: ConfigDiagnostic(severity: .warning, code: .noAddresses, message: MacStrings.addAnAddressBeforeActivating)
        case .noPeers: ConfigDiagnostic(severity: .warning, code: .noPeers, message: MacStrings.addAServerBeforeActivating)
        default: issue
        }
    }

    package static func parts(_ text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        return text.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private var fieldDiagnostics: [EditorDiagnostic] {
        var issues: [EditorDiagnostic] = []
        func issue(_ code: ConfigDiagnostic.Code, _ field: EditorField, message: String? = nil) {
            issues.append(EditorDiagnostic(ConfigDiagnostic(severity: .error, code: code, message: message), fields: [field]))
        }
        if needsPrivateKey {
            issue(.invalidKey, .privateKey)
        }
        for field in keyErrors {
            issue(.invalidKey, field)
        }
        for part in Self.parts(draft.addresses) where (try? IPAddressRange(part)) == nil {
            issue(.invalidCIDR, .addresses)
        }
        for part in Self.parts(draft.dns) where (try? DNSServer(part)) == nil {
            issue(.invalidDNS, .dns)
        }
        if !draft.listenPort.isEmpty, Self.number(draft.listenPort, minimum: 1) == nil {
            issue(.invalidPort, .listenPort)
        }
        if !draft.mtu.isEmpty, Self.number(draft.mtu, minimum: 1) == nil {
            issue(.invalidMTU, .mtu)
        }
        for peer in draft.peers {
            validate(peer, into: &issues)
        }
        for text in draft.exclusions where (try? TunnelExclusions.entry(text)) == nil {
            issue(.invalidCIDR, .exclusions, message: UserStrings.exclusionHostName)
        }
        for problem in draft.onDemandForm.issues {
            let code: ConfigDiagnostic.Code = switch problem {
            case .nameControl: .controlCharacter
            case .duplicate: .duplicateKey
            case .nameLength, .listLimit: .limitExceeded
            }
            issue(code, .onDemand, message: problem.message)
        }
        return issues
    }

    private func validate(_ peer: PeerEditorDraft, into issues: inout [EditorDiagnostic]) {
        func issue(_ code: ConfigDiagnostic.Code, _ field: EditorField, message: String? = nil) {
            issues.append(EditorDiagnostic(ConfigDiagnostic(severity: .error, code: code, message: message), fields: [field]))
        }
        if (try? PublicKey(base64: peer.publicKey)) == nil {
            issue(.invalidKey, .publicKey(peer.id))
        }
        if peer.presharedReference != nil, !hasPresharedKey(peer.id) {
            issue(.invalidKey, .presharedKey(peer.id))
        }
        if !peer.endpoint.isEmpty {
            do { _ = try Endpoint(peer.endpoint) }
            catch { issue(error == .invalidPort ? .invalidPort : .invalidEndpoint, .endpoint(peer.id)) }
        }
        for part in peer.allowedIPs.texts where (try? IPAddressRange(part.trimmingCharacters(in: .whitespaces))) == nil {
            issue(.invalidCIDR, .allowedIPs(peer.id))
        }
        if !peer.keepalive.isEmpty, Self.number(peer.keepalive, minimum: 0) == nil {
            issue(.invalidKeepalive, .keepalive(peer.id), message: EditorStrings.keepaliveLimit)
        }
    }

    private func fields(for issue: ConfigDiagnostic) -> Set<EditorField> {
        switch issue.code {
        case .duplicatePeer:
            Set<EditorField>([.peers]).union(draft.peers.map { .publicKey($0.id) })
        case _ where Self.exclusionMessages.contains(issue.message): [.exclusions]
        case .invalidEndpoint where issue.message == UserStrings.invalidTransport: [.transport]
        case .invalidEndpoint: [.dnsPolicy, .peers]
        default: Self.defaultFields(for: issue.code)
        }
    }

    private static func number(_ text: String, minimum: UInt16) -> UInt16? {
        guard !text.isEmpty, text.utf8.allSatisfy({ (48 ... 57).contains($0) }), let value = UInt16(text),
              value >= minimum else { return nil }
        return value
    }
}
