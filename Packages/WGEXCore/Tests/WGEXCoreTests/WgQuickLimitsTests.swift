// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore

private struct WgQuickLimitsTests {
    @Test(arguments: [262_144, 262_145])
    func `byte cap boundary`(count: Int) throws {
        var bytes = try Array(CodecFixtures.minimal().utf8)
        bytes.append(35); bytes.append(contentsOf: repeatElement(120, count: count - bytes.count))
        try check(&bytes, rejected: count > 262_144)
    }

    @Test(arguments: [4096, 4097])
    func `physical line cap boundary`(count: Int) throws {
        let text = try CodecFixtures.minimal()
        let existing = text.utf8.filter { $0 == 10 }.count
        var bytes = Array((text + String(repeating: "#\n", count: count - existing)).utf8)
        try check(&bytes, rejected: count > 4096)
    }

    @Test(arguments: [1024, 1025])
    func `peer cap boundary with distinct public fixture bytes`(count: Int) throws {
        var text = try "[Interface]\nPrivateKey=\(CodecFixtures.key("client1.key"))\n"
        for number in 0 ..< count {
            var data = Data(repeating: 0, count: 32)
            data[0] = UInt8(truncatingIfNeeded: number); data[1] = UInt8(truncatingIfNeeded: number >> 8)
            text += "[Peer]\nPublicKey=\(data.base64EncodedString())\n"
        }
        var bytes = Array(text.utf8)
        try check(&bytes, rejected: count > 1024)
    }

    @Test(arguments: [4096, 4097])
    func `AllowedIPs cap counts all peers`(count: Int) throws {
        let list = Array(repeating: "10.77.0.0/24", count: count - 1).joined(separator: ",")
        var bytes = try Array((CodecFixtures.minimal() + "[Peer]\nPublicKey=\(CodecFixtures.key("client2.pub"))\nAllowedIPs=\(list)\n")
            .utf8)
        try check(&bytes, rejected: count > 4096)
    }

    @Test(arguments: [64, 65])
    func `DNS cap includes search domains`(count: Int) throws {
        let list = Array(repeating: "corp.example", count: count - 1).joined(separator: ",")
        var bytes = try Array(CodecFixtures.minimal(interface: "DNS=10.77.0.1,\(list)").utf8)
        try check(&bytes, rejected: count > 64)
    }

    @Test(arguments: [1, 128, 129])
    func `profile name cap is applied by named overload`(count: Int) throws {
        var bytes = try Array(CodecFixtures.minimal().utf8)
        do {
            let parsed = try parseWgQuick(&bytes, name: String(repeating: "é", count: count))
            #expect(count <= 128)
            #expect(parsed.profile.name.count == count)
        } catch let ConfigParseError.diagnostics(diagnostics) { #expect(count == 129 && diagnostics.first?.code == .limitExceeded) }
        #expect(bytes.allSatisfy { $0 == 0 })
    }

    @Test
    func `every tightened limit is honoured`() throws {
        let limits = try ParseLimits(
            maximumBytes: 1024,
            maximumLines: 16,
            maximumPeers: 1,
            maximumAllowedIPs: 1,
            maximumDNS: 1,
            maximumNameCharacters: 1,
        )
        let cases = try [
            CodecFixtures.minimal() + "#" + String(repeating: "x", count: 1024),
            CodecFixtures.minimal() + String(repeating: "\n", count: 16),
            CodecFixtures.minimal() + "[Peer]\nPublicKey=\(CodecFixtures.key("client2.pub"))",
            CodecFixtures.minimal().replacingOccurrences(of: "AllowedIPs = 10.77.0.0/24", with: "AllowedIPs = 10.77.0.0/24, ::/0"),
            CodecFixtures.minimal(interface: "DNS=10.77.0.1,corp.example"),
        ]
        for text in cases {
            var bytes = Array(text.utf8)
            do { _ = try parseWgQuick(&bytes, limits: limits); Issue.record("Expected cap failure") }
            catch let ConfigParseError.diagnostics(diagnostics) { #expect(diagnostics.first?.code == .limitExceeded) }
        }
        var bytes = try Array(CodecFixtures.minimal().utf8)
        #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes, name: "XX", limits: limits) }
    }

    @Test
    func `captured secrets are wiped when later parsing fails`() throws {
        let reports = Mutex<[SecretBytes.WipeReport]>([])
        var bytes = try Array(CodecFixtures.minimal(peer: "Endpoint=bad endpoint").utf8)
        SecretBytes.$wipeObserver.withValue({ report in reports.withLock { $0.append(report) } }) {
            #expect(throws: ConfigParseError.self) { _ = try parseWgQuick(&bytes) }
        }
        #expect(bytes.allSatisfy { $0 == 0 })
        #expect(reports.withLock { !$0.isEmpty && $0.allSatisfy(\.isZeroed) })
    }

    @Test
    func `borrowed input remains owned by caller`() throws {
        let bytes = try Array(CodecFixtures.minimal().utf8)
        _ = try parseWgQuick(bytes)
        #expect(bytes.first == 91)
    }

    private func check(_ bytes: inout [UInt8], rejected: Bool) throws {
        do { _ = try parseWgQuick(&bytes); #expect(!rejected) }
        catch let ConfigParseError.diagnostics(diagnostics) {
            #expect(rejected); #expect(diagnostics.first?.code == .limitExceeded)
        }
        #expect(bytes.allSatisfy { $0 == 0 })
    }
}
