// SPDX-License-Identifier: MIT
// Adapted from wombat-vpn Packages/TunnelCore/Sources/TunnelCore/WgQuick.swift at a27bce1b6f25, MIT
// Adapted from wireguard-apple Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift at 2fec12a6e1f6, MIT
import Foundation

/// The borrowed variant does not own the caller's storage. Prefer the wiping inout overload.
/// No complete input or secret value is converted to String.
public func parseWgQuick(
    _ bytes: borrowing [UInt8], limits: ParseLimits = .default,
) throws(ConfigParseError) -> ParsedConfiguration {
    try parseWgQuick(bytes, name: String("Tunnel".prefix(limits.maximumNameCharacters)), limits: limits)
}

public func parseWgQuick(
    _ bytes: borrowing [UInt8], name: String, limits: ParseLimits = .default,
) throws(ConfigParseError) -> ParsedConfiguration {
    do {
        var result: ParsedConfiguration?
        try bytes.withUnsafeBytes { raw in
            var parser = WgQuickParser(raw: raw, limits: limits)
            result = try parser.parse(name: name)
        }
        guard let parsed = consume result else { throw ConfigParseError.invalidUTF8 }
        return parsed
    } catch let error as ConfigParseError { throw error }
    catch { throw .diagnostics([ConfigDiagnostic(severity: .error, code: .invalidKey)]) }
}

/// Wipes the supplied array on success and failure. Any pre-existing COW aliases remain
/// the caller's responsibility; importers should give this overload uniquely owned storage.
public func parseWgQuick(
    _ bytes: inout [UInt8], limits: ParseLimits = .default,
) throws(ConfigParseError) -> ParsedConfiguration {
    defer { wipeConfigurationInput(&bytes) }
    return try parseWgQuick(bytes, limits: limits)
}

public func parseWgQuick(
    _ bytes: inout [UInt8], name: String, limits: ParseLimits = .default,
) throws(ConfigParseError) -> ParsedConfiguration {
    defer { wipeConfigurationInput(&bytes) }
    return try parseWgQuick(bytes, name: name, limits: limits)
}

private func wipeConfigurationInput(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { raw in
        if let base = raw.baseAddress {
            _ = memset_s(base, raw.count, 0, raw.count)
        }
    }
}

private struct WgQuickParser {
    private struct Field {
        let range: Range<Int>
        let line: Int
    }

    private struct Section {
        var fields: [String: Field] = [:]
        var lists: [String: [Field]] = [:]
        let line: Int
    }

    let raw: UnsafeRawBufferPointer
    let limits: ParseLimits
    private var interface: Section?
    private var peers: [Section] = []
    private var current = -1 // -1: outside, 0: interface, 1: peer
    private var diagnostics: [ConfigDiagnostic] = []
    private var replacements: [(Range<Int>, String)] = []
    private var publicKeyRanges: [Range<Int>] = []
    private var ignoredValueRanges: [Range<Int>] = []
    private var references: [SecretRef: Range<Int>] = [:]
    private var secretCount = 0
    private var allowedCount = 0
    private var literalMarkers = Set<String>()
    private var exclusionFields: [Field] = []

    init(raw: UnsafeRawBufferPointer, limits: ParseLimits) {
        self.raw = raw; self.limits = limits
    }

    mutating func parse(name: String) throws -> ParsedConfiguration {
        guard raw.count <= limits.maximumBytes, !name.isEmpty,
              name.count <= limits.maximumNameCharacters else { throw failure(.limitExceeded) }
        guard !name.unicodeScalars
            .contains(where: { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format })
        else { throw failure(.controlCharacter) }
        guard !PublicFieldSafety.containsKey(name.utf8) else { throw publicFieldFailure() }
        try ConfigurationUTF8.validate(raw)
        literalMarkers = SecretPlaceholder.candidates(in: raw)
        try scan()
        guard let interface else { throw failure(.invalidKey) }
        var profile = TunnelProfile(name: name)
        var storage = try SecretBytes(zeroedCount: (peers.count + 1) * 32)
        guard let privateField = interface.fields["privatekey"] else { throw failure(.invalidKey, line: interface.line) }
        let privateRef = uniqueReference()
        profile.secrets.privateKey = privateRef
        try capture(privateField, reference: privateRef, into: &storage)
        let privateBytes = try SecretBytes(copying: storage, range: 0 ..< 32)
        profile.interface.publicKey = try PrivateKey(bytes: consume privateBytes).publicKey()
        try readInterface(interface, into: &profile)
        try readExclusions(into: &profile)
        var seen = Set<PublicKey>()
        for peer in peers {
            let parsed = try readPeer(peer, storage: &storage, profile: &profile)
            if !seen.insert(parsed.publicKey).inserted {
                diagnostics.append(ConfigDiagnostic(severity: .error, code: .duplicatePeer, line: peer.fields["publickey"]?.line))
            }
            profile.peers.append(parsed)
        }
        if let mtu = profile.interface.mtu, !(1280 ... 1500).contains(mtu) {
            diagnostics.append(ConfigDiagnostic(severity: .error, code: .invalidMTU, line: interface.fields["mtu"]?.line))
        }
        guard !diagnostics.contains(where: { $0.severity == .error }) else { throw ConfigParseError.diagnostics(diagnostics) }
        let original = redactedOriginal()
        profile.original = original
        let review = profile.validate()
        let secrets = try ParsedSecrets(bytes: consume storage, references: references)
        return ParsedConfiguration(profile: profile, diagnostics: diagnostics + review, secrets: consume secrets, original: original)
    }

    private func publicFieldFailure(line: Int? = nil) -> ConfigParseError {
        .diagnostics([ConfigDiagnostic(severity: .error, code: .invalidKey, line: line, message: UserStrings.secretInPublicField)])
    }

    private func failure(_ code: ConfigDiagnostic.Code, line: Int? = nil) -> ConfigParseError {
        .diagnostics([ConfigDiagnostic(severity: .error, code: code, line: line)])
    }

    private func trim(_ range: Range<Int>) -> Range<Int> {
        var start = range.lowerBound; var end = range.upperBound
        while start < end, raw[start] == 32 || raw[start] == 9 {
            start += 1
        }
        while end > start, raw[end - 1] == 32 || raw[end - 1] == 9 {
            end -= 1
        }
        return start ..< end
    }

    private func text(_ range: Range<Int>) -> String {
        String(decoding: raw[range], as: UTF8.self)
    }

    private mutating func scan() throws {
        var start = raw.count >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF ? 3 : 0
        var line = 1
        while start < raw.count {
            guard line <= limits.maximumLines else { throw failure(.limitExceeded, line: line) }
            let end = index(of: 10, in: start ..< raw.count) ?? raw.count
            var contentEnd = end
            if contentEnd > start, raw[contentEnd - 1] == 13 {
                guard end < raw.count else { throw failure(.controlCharacter, line: line) }
                contentEnd -= 1
            }
            if index(of: 13, in: start ..< contentEnd) != nil {
                throw failure(.controlCharacter, line: line)
            }
            let comment = index(of: 35, in: start ..< contentEnd) ?? contentEnd
            let range = trim(start ..< comment)
            if !range.isEmpty {
                try scanLine(range, contentEnd: contentEnd, line: line)
            } else if comment < contentEnd {
                try scanDirective(comment + 1 ..< contentEnd, line: line)
            }
            start = end + 1; line += 1
        }
    }

    private mutating func scanLine(_ range: Range<Int>, contentEnd: Int, line: Int) throws {
        if raw[range.lowerBound] == 91 {
            try beginSection(range, line: line)
            return
        }
        guard let equals = raw[range].firstIndex(of: 61) else { throw failure(.unknownKey, line: line) }
        let keyRange = trim(range.lowerBound ..< equals)
        guard keyRange.count <= 19 else { throw failure(.unknownKey, line: line) }
        let key = text(keyRange).lowercased()
        let valueRange = trim(equals + 1 ..< range.upperBound)
        if current == 0, ["table", "fwmark", "saveconfig", "preup", "postup", "predown", "postdown"].contains(key) {
            let hook = ["preup", "postup", "predown", "postdown"].contains(key)
            diagnostics.append(ConfigDiagnostic(severity: .warning, code: hook ? .ignoredHook : .unsupportedSetting, line: line))
            // Include inline comments: they may still be part of a command credential.
            ignoredValueRanges.append(equals + 1 ..< contentEnd)
            return
        }
        if !["privatekey", "presharedkey", "publickey"].contains(key),
           PublicFieldSafety.containsKey(raw[valueRange])
        {
            throw publicFieldFailure(line: line)
        }
        try validateKey(key, line: line)
        let field = Field(range: trim(equals + 1 ..< range.upperBound), line: line)
        try store(field, key: key)
    }

    private mutating func store(_ field: Field, key: String) throws {
        if key == "allowedips" {
            let count = raw[field.range].reduce(1) { $1 == 44 ? $0 + 1 : $0 }
            guard count <= limits.maximumAllowedIPs - allowedCount else { throw failure(.limitExceeded, line: field.line) }
            allowedCount += count
        }
        if current == 0 {
            if ["address", "dns"].contains(key) {
                interface?.lists[key, default: []].append(field)
            } else {
                guard interface?.fields.updateValue(field, forKey: key) == nil else { throw failure(.duplicateKey, line: field.line) }
            }
        } else if key == "allowedips" {
            peers[peers.count - 1].lists[key, default: []].append(field)
        } else {
            guard peers[peers.count - 1].fields.updateValue(field, forKey: key) == nil
            else { throw failure(.duplicateKey, line: field.line) }
        }
    }

    private func validateKey(_ key: String, line: Int) throws {
        if ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"].contains(key) {
            throw failure(.amneziaField, line: line)
        }
        let keys = current == 0 ? ["privatekey", "listenport", "address", "dns", "mtu"] :
            ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]
        guard current >= 0, keys.contains(key) else { throw failure(.unknownKey, line: line) }
    }

    private mutating func beginSection(_ range: Range<Int>, line: Int) throws {
        guard range.count <= 11 else { throw failure(.unknownKey, line: line) }
        switch text(range).lowercased() {
        case "[interface]":
            if interface != nil || !peers.isEmpty {
                throw failure(.duplicateKey, line: line)
            }
            interface = Section(line: line); current = 0
        case "[peer]":
            guard interface != nil else { throw failure(.unknownKey, line: line) }
            guard peers.count < limits.maximumPeers else { throw failure(.limitExceeded, line: line) }
            peers.append(Section(line: line)); current = 1
        case "[device]": throw failure(.amneziaField, line: line)
        default: throw failure(.unknownKey, line: line)
        }
    }

    private func items(_ field: Field) -> [String] {
        text(field.range).split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func number(_ field: Field, code: ConfigDiagnostic.Code, allowZero: Bool = false) throws -> UInt16 {
        let value = text(field.range)
        guard !value.isEmpty, value.utf8.allSatisfy({ (48 ... 57).contains($0) }), let number = UInt16(value), allowZero || number > 0
        else { throw failure(code, line: field.line) }
        return number
    }

    private func ranges(_ field: Field) throws -> [IPAddressRange] {
        try items(field).map {
            do { return try IPAddressRange($0) } catch { throw failure(.invalidCIDR, line: field.line) }
        }
    }

    private func readInterface(_ section: Section, into profile: inout TunnelProfile) throws {
        for field in section.lists["address"] ?? [] {
            profile.interface.addresses += try ranges(field)
        }
        if let field = section.fields["listenport"] {
            profile.interface.listenPort = try number(field, code: .invalidPort)
        }
        if let field = section.fields["mtu"] {
            profile.interface.mtu = try number(field, code: .invalidMTU)
        }
        for field in section.lists["dns"] ?? [] {
            let values = items(field)
            guard values.count <= limits.maximumDNS - profile.interface.dns.count - profile.interface.searchDomains.count
            else { throw failure(
                .limitExceeded,
                line: field.line,
            ) }
            for value in values {
                if let server = try? DNSServer(value) {
                    profile.interface.dns.append(server)
                } else {
                    guard PublicFieldSafety.isSearchDomain(value) else { throw failure(.invalidDNS, line: field.line) }
                    profile.interface.searchDomains.append(value.lowercased())
                }
            }
        }
    }

    private mutating func readPeer(
        _ section: Section,
        storage: inout SecretBytes,
        profile: inout TunnelProfile,
    ) throws -> PeerConfiguration {
        guard let field = section.fields["publickey"] else { throw failure(.invalidKey, line: section.line) }
        let publicKey: PublicKey
        do { publicKey = try PublicKey(parsing: UnsafeRawBufferPointer(rebasing: raw[field.range]), encoding: .base64) }
        catch { throw failure(.invalidKey, line: field.line) }
        publicKeyRanges.append(field.range)
        var peer = PeerConfiguration(publicKey: publicKey, allowedIPs: [])
        if let field = section.fields["presharedkey"] {
            let reference = uniqueReference()
            try capture(field, reference: reference, into: &storage)
            profile.secrets.presharedKeys[publicKey] = reference
            peer.hasPresharedKey = true
        }
        for field in section.lists["allowedips"] ?? [] {
            peer.allowedIPs += try ranges(field)
        }
        if let field = section.fields["endpoint"] {
            do { peer.endpoint = try Endpoint(text(field.range)) }
            catch { throw failure(error == .invalidPort ? .invalidPort : .invalidEndpoint, line: field.line) }
        }
        if let field = section.fields["persistentkeepalive"] {
            if text(field.range).lowercased() != "off" {
                let value = try number(field, code: .invalidKeepalive, allowZero: true)
                peer.persistentKeepalive = value == 0 ? nil : value
            }
        }
        return peer
    }
}

private extension WgQuickParser {
    /// A whole-line `# WGEX-Exclude = ...` comment in [Interface] carries exclusions (DEC-087); other apps ignore it.
    private mutating func scanDirective(_ range: Range<Int>, line: Int) throws {
        let content = trim(range)
        let key = TunnelExclusions.wgQuickKey.lowercased()
        guard current == 0, let equals = raw[content].firstIndex(of: 61),
              text(trim(content.lowerBound ..< equals)).lowercased() == key else { return }
        let valueRange = trim(equals + 1 ..< content.upperBound)
        if PublicFieldSafety.containsKey(raw[valueRange]) {
            throw publicFieldFailure(line: line)
        }
        exclusionFields.append(Field(range: valueRange, line: line))
    }

    private func readExclusions(into profile: inout TunnelProfile) throws {
        for field in exclusionFields {
            for item in items(field) where !item.isEmpty {
                let entry: TunnelExclusions.Entry
                do throws(ConfigurationError) { entry = try TunnelExclusions.entry(item) }
                catch { throw failure(error == .invalidPort ? .invalidPort : .invalidCIDR, line: field.line) }
                if case let .port(port) = entry, port.touchesEphemeralRange {
                    throw failure(.exclusionPortEphemeral, line: field.line)
                }
                profile.exclusions.append(entry)
                guard profile.exclusions.count <= TunnelExclusions.maximumEntries,
                      profile.exclusions.ports.count <= TunnelExclusions.maximumPortEntries
                else { throw failure(.limitExceeded, line: field.line) }
            }
        }
    }

    func index(of byte: Int32, in range: Range<Int>) -> Int? {
        guard let base = raw.baseAddress, let match = memchr(base + range.lowerBound, byte, range.count) else { return nil }
        return base.distance(to: UnsafeRawPointer(match))
    }

    private func uniqueReference() -> SecretRef {
        // Avoid mistaking an existing marker in a comment for an inserted placeholder.
        var reference = SecretRef.daemonStore(id: UUID())
        while literalMarkers.contains(reference.placeholder) || references[reference] != nil {
            reference = .daemonStore(id: UUID())
        }
        return reference
    }

    private mutating func capture(_ field: Field, reference: SecretRef, into storage: inout SecretBytes) throws {
        let target = secretCount * 32 ..< (secretCount + 1) * 32
        do {
            try storage.withUnsafeMutableBytes {
                try ByteCodec.decode(
                    UnsafeRawBufferPointer(rebasing: raw[field.range]),
                    into: UnsafeMutableRawBufferPointer(rebasing: $0[target]),
                    encoding: .base64,
                )
            }
        } catch { throw failure(.invalidKey, line: field.line) }
        secretCount += 1; references[reference] = target
        replacements.append((field.range, reference.placeholder))
    }

    private func redactedOriginal() -> OriginalText {
        OriginalText(redacting: raw, secrets: replacements, publicKeys: publicKeyRanges, ignoredValues: ignoredValueRanges)
    }
}
