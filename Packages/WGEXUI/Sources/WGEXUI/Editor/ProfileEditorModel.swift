// SPDX-License-Identifier: MIT
import Foundation
import Observation
import WGEXCore

/// UI-owned draft. Keys stay in wiped buffers; printable representations are redacted.
@MainActor @Observable
public final class ProfileEditorModel: CustomStringConvertible, CustomReflectable {
    public var draft: ProfileEditorDraft {
        didSet { validationRevision += 1 }
    }

    public private(set) var publicKey: PublicKey {
        didSet { validationRevision += 1 }
    }

    /// True while the owner is persisting a validated snapshot and its keys.
    public private(set) var isSaving = false
    public var showsDiscardConfirmation = false
    public private(set) var actionFailed = false
    public var featureFlags: FeatureFlags
    /// The iOS on-demand editor (M06-T06). A change writes the draft's policy: the stored one while the form matches it,
    /// otherwise the form's own; the macOS form is reset to that policy so it never rewrites it.
    public var iosOnDemand: IOSOnDemandForm {
        didSet { applyIOSOnDemand() }
    }

    public let publicKeysInUse: Set<PublicKey>
    /// DEC-088, Mac only: a new or still incomplete tunnel saves with a name and a key alone; a missing address or server
    /// is then a warning that blocks activation, not saving. Off (iPhone, iPad, TV) keeps the full `validate()` gate.
    public let allowsIncomplete: Bool

    @ObservationIgnored package let sourceProfile: TunnelProfile
    @ObservationIgnored private var initialDraft: ProfileEditorDraft
    @ObservationIgnored private var privateKey: EditorSecret?
    @ObservationIgnored private var presharedKeys: [UUID: EditorSecret] = [:]
    @ObservationIgnored private var initialPrivateKey: EditorSecret?
    @ObservationIgnored private var initialPresharedKeys: [UUID: EditorSecret] = [:]
    /// Explicit observation token; noncopyable buffers cannot use Observation's generated accessor.
    private var secretRevision = 0 {
        didSet { validationRevision += 1 }
    }

    private var baselineRevision = 0
    private var retainsOriginal = true
    public private(set) var keyErrors: Set<EditorField> = [] {
        didSet { validationRevision += 1 }
    }

    package var validationRevision = 0
    /// Counts key changes made outside a key row (a generated pair, a cleared preshared key, a removed server, Edit as Text),
    /// so a revealed row hides instead of showing a key the model no longer holds.
    public private(set) var keyResetRevision = 0
    @ObservationIgnored package var cachedValidation: (revision: Int, diagnostics: [EditorDiagnostic])?

    public init(
        profile: TunnelProfile = TunnelProfile(name: ""),
        featureFlags: FeatureFlags = .defaults,
        publicKeysInUse: Set<PublicKey> = [],
        allowsIncomplete: Bool = false,
    ) {
        let initial = ProfileEditorDraft(profile)
        sourceProfile = profile; draft = initial; initialDraft = initial
        iosOnDemand = IOSOnDemandForm(policy: profile.onDemand)
        publicKey = profile.interface.publicKey; self.featureFlags = featureFlags; self.publicKeysInUse = publicKeysInUse
        self.allowsIncomplete = allowsIncomplete
    }

    public convenience init(
        profile: TunnelProfile,
        secrets: borrowing ParsedSecrets,
        featureFlags: FeatureFlags = .defaults,
        publicKeysInUse: Set<PublicKey> = [],
        allowsIncomplete: Bool = false,
    ) throws {
        self.init(profile: profile, featureFlags: featureFlags, publicKeysInUse: publicKeysInUse, allowsIncomplete: allowsIncomplete)
        privateKey = try secrets.withKey(profile.secrets.privateKey) { try EditorSecret(SecretBytes(copying: $0)) }
        // Derive rather than trusting the caller's public metadata.
        publicKey = try PrivateKey(bytes: privateKeyCopy()).publicKey()
        for peer in draft.peers {
            if let ref = peer.presharedReference {
                presharedKeys[peer.id] = try secrets.withKey(ref) { try EditorSecret(SecretBytes(copying: $0)) }
            }
        }
        initialPrivateKey = privateKey; initialPresharedKeys = presharedKeys
    }

    public var description: String {
        "ProfileEditorModel(<redacted>)"
    }

    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }

    public var isDirty: Bool {
        _ = secretRevision
        return draft != initialDraft || !sameSecrets || !keyErrors.isEmpty || iosOnDemandEdited
    }

    public var canSave: Bool {
        !diagnostics.contains { $0.diagnostic.severity == .error } && !(iosOnDemandEdited && !iosOnDemand.issues.isEmpty)
    }

    /// True when the iOS on-demand form differs from the saved policy; its list problems then block a save.
    public var iosOnDemandEdited: Bool {
        iosOnDemand != IOSOnDemandForm(policy: initialDraft.onDemand)
    }

    /// True while the keys hold exactly what the editor opened with, so the owner can keep the stored key items and their
    /// references instead of writing new ones (an on-demand or name edit never touches the Keychain).
    public var keysUnchanged: Bool {
        _ = secretRevision
        return initialPrivateKey != nil && sameSecrets
    }

    public var needsPrivateKey: Bool {
        _ = secretRevision; return privateKey == nil
    }

    public func requestDiscard() -> Bool {
        showsDiscardConfirmation = isDirty
        return !isDirty
    }

    /// Call only after the owner has successfully stored the profile and keys.
    public func markSaved() {
        if isDirty {
            retainsOriginal = false
        }
        initialDraft = draft; initialPrivateKey = privateKey; initialPresharedKeys = presharedKeys
        baselineRevision = secretRevision
    }

    /// Marks the draft saved only after the owner's asynchronous transaction succeeds.
    public func save(using persist: (TunnelProfile, borrowing ParsedSecrets) async throws -> Void) async throws {
        guard !isSaving else { return }
        isSaving = true
        defer { isSaving = false }
        let profile = try validatedProfile()
        let secrets = try makeSecrets()
        try await persist(profile, secrets)
        markSaved()
    }

    public func generateKeypair() {
        do {
            let key = try PrivateKey.generate()
            var bytes = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &bytes)
            publicKey = try key.publicKey(); privateKey = EditorSecret(consume bytes)
            keyErrors.remove(.privateKey); secretRevision += 1; actionFailed = false; keyResetRevision += 1
        } catch { actionFailed = true }
    }

    public func setPrivateKey(_ text: borrowing SecretBytes) throws {
        do {
            let key = try PrivateKey(parsing: text, encoding: .base64)
            var bytes = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &bytes)
            publicKey = try key.publicKey(); privateKey = EditorSecret(consume bytes)
            keyErrors.remove(.privateKey); secretRevision += 1
        } catch { keyErrors.insert(.privateKey); throw error }
    }

    public func setPresharedKey(_ text: borrowing SecretBytes, peerID: UUID) throws {
        guard let index = draft.peers.firstIndex(where: { $0.id == peerID }) else { return }
        do {
            let key = try PresharedKey(parsing: text, encoding: .base64)
            var bytes = try SecretBytes(zeroedCount: 32)
            try key.encode(into: &bytes)
            presharedKeys[peerID] = EditorSecret(consume bytes)
            if draft.peers[index].presharedReference == nil {
                draft.peers[index].presharedReference = .daemonStore(id: UUID())
            }
            keyErrors.remove(.presharedKey(peerID)); secretRevision += 1
        } catch { keyErrors.insert(.presharedKey(peerID)); throw error }
    }

    public func removePresharedKey(peerID: UUID) {
        guard let index = draft.peers.firstIndex(where: { $0.id == peerID }) else { return }
        presharedKeys[peerID] = nil; draft.peers[index].presharedReference = nil
        keyErrors.remove(.presharedKey(peerID)); secretRevision += 1; keyResetRevision += 1
    }

    /// For SecretField's buffer only; callers must not retain or log the returned text.
    public func privateKeyForField() -> String? {
        _ = secretRevision; return privateKey?.fieldText()
    }

    public func presharedKeyForField(peerID: UUID) -> String? {
        _ = secretRevision; return presharedKeys[peerID]?.fieldText()
    }

    public func addPeer() {
        draft.peers.append(PeerEditorDraft())
    }

    public func removePeer(id: UUID) {
        draft.peers.removeAll { $0.id == id }; presharedKeys[id] = nil
        keyErrors = keyErrors.filter { $0 != .presharedKey(id) }; keyResetRevision += 1
    }

    public func movePeers(from offsets: IndexSet, to destination: Int) {
        guard destination >= 0, destination <= draft.peers.count, offsets.allSatisfy({ draft.peers.indices.contains($0) }) else { return }
        let moving = offsets.sorted().map { draft.peers[$0] }
        let insertion = destination - offsets.filter { $0 < destination }.count
        for index in offsets.sorted().reversed() {
            draft.peers.remove(at: index)
        }
        draft.peers.insert(contentsOf: moving, at: insertion)
    }

    public func allTraffic(peerID: UUID) {
        guard let index = draft.peers.firstIndex(where: { $0.id == peerID }) else { return }
        draft.peers[index].allowedIPs.setAllTraffic()
    }

    public func excludePrivateNetworks(peerID: UUID) {
        setPrivateNetworksExcluded(true, peerID: peerID)
    }

    /// Turns a peer's "Exclude private networks" control on or off with the draft's DNS servers (DEC-020).
    public func setPrivateNetworksExcluded(_ isOn: Bool, peerID: UUID) {
        guard let index = draft.peers.firstIndex(where: { $0.id == peerID }) else { return }
        draft.peers[index].allowedIPs.setPrivateNetworksExcluded(isOn, dnsServers: Self.parts(draft.dns))
    }

    /// A validated public profile. Edits invalidate retained original text.
    public func validatedProfile() throws -> TunnelProfile {
        guard canSave else { throw ConfigValidationError(diagnostics: diagnostics.map(\.diagnostic)) }
        var result = candidateProfile
        if isDirty || !retainsOriginal {
            result.original = nil; result.updatedAt = Date()
        }
        return result
    }

    /// Explicit buffer export to the owner's storage transaction, never a String.
    public func makeSecrets() throws -> ParsedSecrets {
        guard let privateKey else { throw ConfigurationError.invalidSecretReference }
        var packed = try SecretBytes(zeroedCount: 32 * (1 + draft.peers.filter { $0.presharedReference != nil }.count))
        try privateKey.write(into: &packed, offset: 0)
        var references: [SecretRef: Range<Int>] = [sourceProfile.secrets.privateKey: 0 ..< 32]
        var offset = 32
        for peer in draft.peers {
            if let ref = peer.presharedReference {
                guard let key = presharedKeys[peer.id] else { throw ConfigurationError.invalidSecretReference }
                try key.write(into: &packed, offset: offset); references[ref] = offset ..< offset + 32; offset += 32
            }
        }
        return try ParsedSecrets(bytes: consume packed, references: references)
    }

    /// Whether `text` is a base64 WireGuard key (32 bytes), checked without touching the draft or its key errors.
    package static func isKeyText(_ text: borrowing SecretBytes) -> Bool {
        (try? PresharedKey(parsing: text, encoding: .base64)) != nil
    }

    package func hasPresharedKey(_ id: UUID) -> Bool {
        _ = secretRevision; return presharedKeys[id] != nil
    }

    private func applyIOSOnDemand() {
        let policy = iosOnDemand.resolved(against: initialDraft.onDemand)
        guard draft.onDemand != policy else { return }
        draft.onDemand = policy
        draft.onDemandForm = MacOnDemandForm(policy: policy)
    }

    private func privateKeyCopy() throws -> SecretBytes {
        guard let privateKey else { throw ConfigurationError.invalidSecretReference }
        return try privateKey.copy()
    }

    private var sameSecrets: Bool {
        guard secretRevision != baselineRevision else { return true }
        let samePrivate: Bool = if let privateKey, let initialPrivateKey {
            privateKey.equals(initialPrivateKey)
        } else {
            privateKey == nil && initialPrivateKey == nil
        }
        return samePrivate && presharedKeys.keys == initialPresharedKeys.keys && presharedKeys.allSatisfy { id, key in
            initialPresharedKeys[id].map { key.equals($0) } ?? false
        }
    }
}

// MARK: - Edit as Text

public extension ProfileEditorModel {
    /// Whether the form can be written as a WireGuard file without losing anything typed: a key is present and every field
    /// parses. Edit as Text is offered only then.
    var canEditAsText: Bool {
        !hasFieldErrors
    }

    /// The tunnel as a WireGuard file, keys included, for the Mac's Edit as Text buffer. The caller owns the String only while
    /// the text view shows it and drops it on return, close and deactivation; it must never be logged or retained.
    func configurationTextForEditing() throws -> String {
        let text = try serialiseWgQuick(candidateProfile, secrets: makeSecrets())
        return text.bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }

    /// Replaces the interface, exclusions and servers with those of a WireGuard file, as Edit as Text's return to the form and
    /// its Save do. Name, protection, on-demand and start-up stay from the form; a server whose public key is unchanged keeps its
    /// identity and preshared key reference. `bytes` is wiped. Throws the parser's problems and changes nothing on failure;
    /// returns the parser's warnings (removed commands and settings).
    @discardableResult
    func applyConfigurationText(_ bytes: inout [UInt8]) throws(ConfigParseError) -> [ConfigDiagnostic] {
        // The file carries no name; the form's name is kept, so the parser gets a fixed valid one.
        let parsed = try parseWgQuick(&bytes, name: "Tunnel")
        do {
            let profile = parsed.profile
            let key = try parsed.secrets.withKey(profile.secrets.privateKey) { try EditorSecret(SecretBytes(copying: $0)) }
            var next = draft
            // DNS first: its host-route sync must not touch the servers the text supplies.
            next.dns = profile.interface.dns.map(\.stringRepresentation).joined(separator: ", ")
            next.addresses = profile.interface.addresses.map(\.stringRepresentation).joined(separator: ", ")
            next.listenPort = profile.interface.listenPort.map(String.init) ?? ""
            next.mtu = profile.interface.mtu.map(String.init) ?? ""
            next.searchDomains = profile.interface.searchDomains.joined(separator: ", ")
            next.exclusions = profile.exclusions.entries.map(\.text)
            var keys: [UUID: EditorSecret] = [:]
            next.peers = try profile.peers.map { peer in
                let existing = draft.peers.first { $0.publicKey == peer.publicKey.base64 }
                var item = PeerEditorDraft(id: existing?.id ?? UUID())
                item.publicKey = peer.publicKey.base64
                item.endpoint = peer.endpoint?.stringRepresentation ?? ""
                item.allowedIPs = AllowedIPsModel(peer.allowedIPs.map(\.stringRepresentation))
                item.keepalive = peer.persistentKeepalive.map(String.init) ?? ""
                if let reference = profile.secrets.presharedKeys[peer.publicKey] {
                    item.presharedReference = existing?.presharedReference ?? .daemonStore(id: UUID())
                    keys[item.id] = try parsed.secrets.withKey(reference) { try EditorSecret(SecretBytes(copying: $0)) }
                }
                return item
            }
            draft = next
            publicKey = profile.interface.publicKey; privateKey = key; presharedKeys = keys
            keyErrors = []; secretRevision += 1; keyResetRevision += 1
        } catch { throw ConfigParseError.diagnostics([ConfigDiagnostic(severity: .error, code: .invalidKey)]) }
        let parserOnly: Set<ConfigDiagnostic.Code> = [.ignoredHook, .unsupportedSetting, .unknownKey, .amneziaField]
        return parsed.diagnostics.filter { $0.severity == .warning && parserOnly.contains($0.code) }
    }
}
