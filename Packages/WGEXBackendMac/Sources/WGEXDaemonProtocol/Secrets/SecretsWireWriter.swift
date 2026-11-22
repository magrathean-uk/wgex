// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Writes the secrets wire layout into a wiped buffer that grows by
/// reallocation (the old buffer is wiped when it is replaced). Append every
/// preshared key before the first carrier credential.
public struct SecretsWireWriter: ~Copyable {
    private var buffer: SecretBytes
    private var length = 0
    private var peerKeys: [PublicKey] = []
    private var carrierCountOffset: Int?
    private var carrierIDs: [TransportID] = []

    /// Starts a layout with the interface private key.
    public init(privateKey: borrowing SecretBytes) throws(SecretsWireError) {
        guard privateKey.count == SecretsWireLayout.keyLength else {
            throw .invalidKeyLength(privateKey.count)
        }
        // The header is written into a local buffer first: a noncopyable stored
        // property cannot be initialised conditionally on a throwing path.
        var header = try Self.allocate(256)
        header.withUnsafeMutableBytes { $0[0] = SecretsWireLayout.version }
        do {
            try privateKey.copyBytes(into: &header, at: 1)
        } catch {
            throw .allocation(error)
        }
        buffer = header
        length = 1 + SecretsWireLayout.keyLength + 2
    }

    /// Appends a peer's preshared key.
    public mutating func appendPresharedKey(_ key: borrowing SecretBytes, for peer: PublicKey) throws(SecretsWireError) {
        guard carrierCountOffset == nil else { throw .peerAfterCarrier }
        guard key.count == SecretsWireLayout.keyLength else { throw .invalidKeyLength(key.count) }
        guard !peerKeys.contains(peer) else { throw .duplicatePeer }
        guard peerKeys.count < Int(UInt16.max) else { throw .tooManyEntries }
        try appendBytes(Array(peer.rawValue))
        try appendSecret(key)
        peerKeys.append(peer)
        patchUInt16(UInt16(peerKeys.count), at: 1 + SecretsWireLayout.keyLength)
    }

    /// Appends a carrier credential.
    public mutating func appendCarrierCredential(_ credential: borrowing SecretBytes, for transport: TransportID) throws(SecretsWireError) {
        guard credential.count <= Int(UInt16.max) else { throw .credentialTooLong(credential.count) }
        guard !carrierIDs.contains(transport) else { throw .duplicateCarrier }
        guard carrierIDs.count < Int(UInt16.max) else { throw .tooManyEntries }
        if carrierCountOffset == nil {
            carrierCountOffset = length
            try appendBytes([0, 0])
        }
        let uuid = transport.rawValue.uuid
        try appendBytes([
            uuid.0, uuid.1, uuid.2, uuid.3, uuid.4, uuid.5, uuid.6, uuid.7,
            uuid.8, uuid.9, uuid.10, uuid.11, uuid.12, uuid.13, uuid.14, uuid.15,
        ])
        try appendBytes([UInt8(credential.count >> 8), UInt8(credential.count & 0xFF)])
        try appendSecret(credential)
        carrierIDs.append(transport)
        if let offset = carrierCountOffset {
            patchUInt16(UInt16(carrierIDs.count), at: offset)
        }
    }

    /// Finishes the layout and returns an exactly sized buffer.
    public consuming func finish() throws(SecretsWireError) -> SecretBytes {
        if carrierCountOffset == nil {
            try appendBytes([0, 0])
        }
        do {
            return try SecretBytes(copying: buffer, range: 0 ..< length)
        } catch {
            throw .allocation(error)
        }
    }

    private mutating func reserve(_ extra: Int) throws(SecretsWireError) {
        guard length + extra > buffer.count else { return }
        let capacity = min(SecretBytes.maximumCount, max(buffer.count * 2, length + extra))
        guard capacity >= length + extra else { throw .tooManyEntries }
        var grown = try Self.allocate(capacity)
        do {
            let used = try SecretBytes(copying: buffer, range: 0 ..< length)
            try used.copyBytes(into: &grown, at: 0)
        } catch {
            throw .allocation(error)
        }
        buffer = grown
    }

    private static func allocate(_ count: Int) throws(SecretsWireError) -> SecretBytes {
        do {
            return try SecretBytes(zeroedCount: count)
        } catch {
            throw .allocation(error)
        }
    }

    private mutating func appendBytes(_ bytes: [UInt8]) throws(SecretsWireError) {
        try reserve(bytes.count)
        let start = length
        buffer.withUnsafeMutableBytes { target in
            for (position, byte) in bytes.enumerated() {
                target[start + position] = byte
            }
        }
        length += bytes.count
    }

    private mutating func appendSecret(_ secret: borrowing SecretBytes) throws(SecretsWireError) {
        try reserve(secret.count)
        do {
            try secret.copyBytes(into: &buffer, at: length)
        } catch {
            throw .allocation(error)
        }
        length += secret.count
    }

    private mutating func patchUInt16(_ value: UInt16, at offset: Int) {
        buffer.withUnsafeMutableBytes { target in
            target[offset] = UInt8(value >> 8)
            target[offset + 1] = UInt8(value & 0xFF)
        }
    }
}
