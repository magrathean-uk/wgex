// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Binary layout of the `secrets` argument of `start` and
/// `setStartBeforeLogin` (02 §5). Integers are big-endian:
///
///     u8 version=1 | 32 B private key
///     | u16 count | count × (32 B peer public key | 32 B preshared key)
///     | u16 carrierCount | carrierCount × (16 B transport id | u16 len | len bytes)
///
/// Everything is written into and parsed from ``SecretBytes``; nothing
/// passes through `String` or `Codable`.
public enum SecretsWireLayout {
    /// Layout version.
    public static let version: UInt8 = 1
    /// Length of every key.
    public static let keyLength = 32
    /// Length of a transport identifier.
    public static let transportIDLength = 16

    /// Parses a received buffer, taking ownership of it.
    public static func decode(_ wire: consuming SecretBytes) throws(SecretsWireError) -> SecretBundle {
        let index = try wire.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws(SecretsWireError) -> SecretBundle.Index in
            try parseIndex(raw)
        }
        return SecretBundle(storage: wire, index: index)
    }

    /// Copies `data` into a secret buffer, zeroes `data`, then parses it.
    public static func decode(wiping data: inout Data) throws(SecretsWireError) -> SecretBundle {
        let wire: SecretBytes
        do {
            wire = try SecretBytes(wiping: &data)
        } catch {
            throw .allocation(error)
        }
        return try decode(wire)
    }

    /// Parses the received XPC allocation directly, then retains only a uniquely owned SecretBytes copy.
    /// XPC transfers this buffer for one request. Aliases must not be read concurrently: all are erased.
    /// Unlike Data mutation, this intentionally wipes the borrowed allocation without a COW detachment.
    public static func decodeReceived(_ data: Data) throws -> SecretBundle {
        try data.withUnsafeBytes { raw in
            defer { wipeReceivedBytes(raw) }
            let index = try parseIndex(raw)
            return try SecretBundle(storage: SecretBytes(copying: raw), index: index)
        }
    }

    /// Erases a transferred XPC argument even when authentication or decoding rejects the request.
    public static func wipeReceived(_ data: Data) {
        data.withUnsafeBytes { wipeReceivedBytes($0) }
    }

    private static func wipeReceivedBytes(_ raw: UnsafeRawBufferPointer) {
        if let base = raw.baseAddress, !raw.isEmpty {
            _ = memset_s(UnsafeMutableRawPointer(mutating: base), raw.count, 0, raw.count)
        }
    }

    private static func parseIndex(_ raw: UnsafeRawBufferPointer) throws(SecretsWireError) -> SecretBundle.Index {
        var reader = WireReader(raw: raw)
        let found = try reader.readByte()
        guard found == version else {
            throw .unsupportedVersion(found)
        }
        let privateKeyOffset = try reader.skip(keyLength)
        var peers: [SecretBundle.PeerEntry] = []
        for _ in try 0 ..< (reader.readUInt16()) {
            let publicKey = try reader.readPublicKey()
            guard !peers.contains(where: { $0.publicKey == publicKey }) else {
                throw .duplicatePeer
            }
            try peers.append(SecretBundle.PeerEntry(publicKey: publicKey, keyOffset: reader.skip(keyLength)))
        }
        var carriers: [SecretBundle.CarrierEntry] = []
        for _ in try 0 ..< (reader.readUInt16()) {
            let id = try reader.readTransportID()
            guard !carriers.contains(where: { $0.id == id }) else {
                throw .duplicateCarrier
            }
            let length = try Int(reader.readUInt16())
            try carriers.append(SecretBundle.CarrierEntry(id: id, offset: reader.skip(length), length: length))
        }
        guard reader.isAtEnd else {
            throw .trailingBytes
        }
        return SecretBundle.Index(privateKeyOffset: privateKeyOffset, peers: peers, carriers: carriers)
    }
}

/// Sequential bounds-checked reader over the wire bytes.
private struct WireReader {
    let raw: UnsafeRawBufferPointer
    var offset = 0

    var isAtEnd: Bool {
        offset == raw.count
    }

    mutating func skip(_ length: Int) throws(SecretsWireError) -> Int {
        guard length >= 0, raw.count - offset >= length else {
            throw .truncated
        }
        defer { offset += length }
        return offset
    }

    mutating func readByte() throws(SecretsWireError) -> UInt8 {
        try raw[skip(1)]
    }

    mutating func readUInt16() throws(SecretsWireError) -> UInt16 {
        let start = try skip(2)
        return UInt16(raw[start]) << 8 | UInt16(raw[start + 1])
    }

    mutating func readPublicKey() throws(SecretsWireError) -> PublicKey {
        let start = try skip(SecretsWireLayout.keyLength)
        do {
            return try PublicKey(rawValue: Data(raw[start ..< start + SecretsWireLayout.keyLength]))
        } catch {
            throw .invalidKeyLength(SecretsWireLayout.keyLength)
        }
    }

    mutating func readTransportID() throws(SecretsWireError) -> TransportID {
        let start = try skip(SecretsWireLayout.transportIDLength)
        let bytes = Array(raw[start ..< start + SecretsWireLayout.transportIDLength])
        let uuid = UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ))
        return TransportID(rawValue: uuid)
    }
}
