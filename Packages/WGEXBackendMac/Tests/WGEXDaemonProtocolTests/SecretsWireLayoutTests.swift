// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
@testable import WGEXCore
import WGEXDaemonProtocol

private struct SecretsWireLayoutTests {
    private final class Reports: Sendable {
        let items = Mutex<[SecretBytes.WipeReport]>([])
    }

    private static func patterned(_ seed: UInt8, count: Int = 32) throws -> SecretBytes {
        var secret = try SecretBytes(zeroedCount: count)
        secret.withUnsafeMutableBytes { raw in
            for index in raw.indices {
                raw[index] = seed &+ UInt8(truncatingIfNeeded: index)
            }
        }
        return secret
    }

    private static func publicKey(_ seed: UInt8) throws -> PublicKey {
        try PublicKey(rawValue: Data(repeating: seed, count: 32))
    }

    private static func encodeSample(peer: PublicKey, transport: TransportID) throws -> SecretBytes {
        var writer = try SecretsWireWriter(privateKey: patterned(1))
        try writer.appendPresharedKey(patterned(2), for: peer)
        try writer.appendPresharedKey(patterned(3), for: publicKey(0xBB))
        try writer.appendCarrierCredential(patterned(4, count: 5), for: transport)
        return try writer.finish()
    }

    @Test
    func `layout round-trips`() throws {
        let peer = try Self.publicKey(0xAA)
        let transport = TransportID()
        let wire = try Self.encodeSample(peer: peer, transport: transport)
        #expect(wire.count == 1 + 32 + 2 + 2 * 64 + 2 + 16 + 2 + 5)
        let bundle = try SecretsWireLayout.decode(wire)
        #expect(try bundle.presharedKeyPeers == [peer, Self.publicKey(0xBB)])
        #expect(bundle.carrierIDs == [transport])
        let privateKey = try bundle.privateKey()
        let expectedPrivate = try Self.patterned(1)
        let privateMatches = privateKey.constantTimeEquals(expectedPrivate)
        #expect(privateMatches)
        let expectedPSK = try Self.patterned(2)
        var pskMatches = false
        if let psk = try bundle.presharedKey(for: peer) {
            pskMatches = psk.constantTimeEquals(expectedPSK)
        }
        #expect(pskMatches)
        var credentialCount = 0
        if let credential = try bundle.carrierCredential(for: transport) {
            credentialCount = credential.count
        }
        #expect(credentialCount == 5)
        var foundUnknownPeer = false
        if let _ = try bundle.presharedKey(for: Self.publicKey(0xCC)) {
            foundUnknownPeer = true
        }
        #expect(!foundUnknownPeer)
    }

    @Test
    func `layout without peers or carriers is three bytes of counts`() throws {
        let wire = try SecretsWireWriter(privateKey: Self.patterned(9)).finish()
        #expect(wire.count == 1 + 32 + 2 + 2)
        let bundle = try SecretsWireLayout.decode(wire)
        #expect(bundle.presharedKeyPeers.isEmpty)
        #expect(bundle.carrierIDs.isEmpty)
    }

    @Test
    func `received XPC Data and its alias are wiped in place`() throws {
        let wire = try Self.encodeSample(peer: Self.publicKey(0xAA), transport: TransportID())
        let data = wire.withUnsafeBytes { Data($0) }
        let alias = data
        let bundle = try SecretsWireLayout.decodeReceived(data)
        let originalZeroed = data.allSatisfy { $0 == 0 }
        let aliasZeroed = alias.allSatisfy { $0 == 0 }
        #expect(originalZeroed && aliasZeroed)
        #expect(bundle.wireByteCount == wire.count)
    }

    @Test
    func `every buffer is wiped when released`() throws {
        let reports = Reports()
        try SecretBytes.$wipeObserver.withValue({ report in reports.items.withLock { $0.append(report) } }) {
            let wire = try Self.encodeSample(peer: Self.publicKey(0xAA), transport: TransportID())
            let bundle = try SecretsWireLayout.decode(wire)
            _ = try bundle.privateKey()
            _ = consume bundle
        }
        let wiped = reports.items.withLock { $0 }
        #expect(!wiped.isEmpty)
        let allZeroed = wiped.allSatisfy(\.isZeroed)
        #expect(allZeroed)
    }

    @Test
    func `malformed layouts are refused`() throws {
        let wire = try Self.encodeSample(peer: Self.publicKey(0xAA), transport: TransportID())
        let bytes = wire.withUnsafeBytes { Array($0) }
        #expect(throws: SecretsWireError.truncated) { _ = try Self.decode(Array(bytes.dropLast())) }
        #expect(throws: SecretsWireError.trailingBytes) { _ = try Self.decode(bytes + [0]) }
        var wrongVersion = bytes
        wrongVersion[0] = 2
        #expect(throws: SecretsWireError.unsupportedVersion(2)) { _ = try Self.decode(wrongVersion) }
        #expect(throws: SecretsWireError.truncated) { _ = try Self.decode([1]) }
        var duplicate = bytes
        duplicate.replaceSubrange(35 + 64 ..< 35 + 96, with: bytes[35 ..< 67])
        #expect(throws: SecretsWireError.duplicatePeer) { _ = try Self.decode(duplicate) }
    }

    @Test
    func `writer enforces order and lengths`() throws {
        #expect(throws: SecretsWireError.invalidKeyLength(31)) {
            _ = try SecretsWireWriter(privateKey: Self.patterned(1, count: 31))
        }
        var writer = try SecretsWireWriter(privateKey: Self.patterned(1))
        try writer.appendCarrierCredential(Self.patterned(4, count: 3), for: TransportID())
        #expect(throws: SecretsWireError.peerAfterCarrier) {
            try writer.appendPresharedKey(Self.patterned(2), for: Self.publicKey(0xAA))
        }
        let peer = try Self.publicKey(0xAA)
        var second = try SecretsWireWriter(privateKey: Self.patterned(1))
        try second.appendPresharedKey(Self.patterned(2), for: peer)
        #expect(throws: SecretsWireError.duplicatePeer) { try second.appendPresharedKey(Self.patterned(3), for: peer) }
    }

    @Test
    func `writer grows past its initial buffer`() throws {
        var writer = try SecretsWireWriter(privateKey: Self.patterned(1))
        for seed in 0 ..< 40 {
            try writer.appendPresharedKey(Self.patterned(UInt8(seed)), for: Self.publicKey(UInt8(seed)))
        }
        let bundle = try SecretsWireLayout.decode(writer.finish())
        #expect(bundle.presharedKeyPeers.count == 40)
    }

    private static func decode(_ bytes: [UInt8]) throws -> Int {
        var secret = try SecretBytes(zeroedCount: bytes.count)
        secret.withUnsafeMutableBytes { $0.copyBytes(from: bytes) }
        return try SecretsWireLayout.decode(secret).wireByteCount
    }
}
