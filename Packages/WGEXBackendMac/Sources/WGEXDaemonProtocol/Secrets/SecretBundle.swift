// SPDX-License-Identifier: MIT

import WGEXCore

/// Parsed secrets: the wire buffer plus an index of offsets. Key material stays
/// in the one wiped buffer until a caller copies a key out explicitly.
public struct SecretBundle: ~Copyable, Sendable {
    /// Position of one preshared key (public keys are not secret).
    package struct PeerEntry: Sendable, Hashable {
        package let publicKey: PublicKey
        package let keyOffset: Int
    }

    /// Position of one carrier credential.
    package struct CarrierEntry: Sendable, Hashable {
        package let id: TransportID
        package let offset: Int
        package let length: Int
    }

    /// Offsets into the wire buffer.
    package struct Index: Sendable, Hashable {
        package let privateKeyOffset: Int
        package let peers: [PeerEntry]
        package let carriers: [CarrierEntry]
    }

    private let storage: SecretBytes
    private let index: Index

    package init(storage: consuming SecretBytes, index: Index) {
        self.storage = storage
        self.index = index
    }

    /// Peers that have a preshared key, in wire order.
    public var presharedKeyPeers: [PublicKey] {
        index.peers.map(\.publicKey)
    }

    /// Transports that have a credential, in wire order.
    public var carrierIDs: [TransportID] {
        index.carriers.map(\.id)
    }

    /// Length of the wire encoding.
    public var wireByteCount: Int {
        storage.count
    }

    /// Copies the private key out.
    public func privateKey() throws(SecretsWireError) -> SecretBytes {
        try copy(offset: index.privateKeyOffset, length: SecretsWireLayout.keyLength)
    }

    /// Copies the preshared key for `peer` out, if present.
    public func presharedKey(for peer: PublicKey) throws(SecretsWireError) -> SecretBytes? {
        guard let entry = index.peers.first(where: { $0.publicKey == peer }) else { return nil }
        return try copy(offset: entry.keyOffset, length: SecretsWireLayout.keyLength)
    }

    /// Copies the credential for `transport` out, if present.
    public func carrierCredential(for transport: TransportID) throws(SecretsWireError) -> SecretBytes? {
        guard let entry = index.carriers.first(where: { $0.id == transport }) else { return nil }
        return try copy(offset: entry.offset, length: entry.length)
    }

    /// Copies the whole wire encoding out (for persisting to the daemon store).
    public func wireBytes() throws(SecretsWireError) -> SecretBytes {
        try copy(offset: 0, length: storage.count)
    }

    private func copy(offset: Int, length: Int) throws(SecretsWireError) -> SecretBytes {
        do {
            return try SecretBytes(copying: storage, range: offset ..< offset + length)
        } catch {
            throw .allocation(error)
        }
    }
}
