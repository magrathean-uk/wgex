// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

/// Only repository throwaway keys enter these helpers.
package enum CodecFixtures {
    package static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    package static func conf(_ name: String) throws -> [UInt8] {
        try Array(Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/conf/\(name).conf")))
    }

    package static func key(_ name: String) throws -> String {
        let file = try String(contentsOf: root.appendingPathComponent("Tests/Fixtures/keys/\(name)"), encoding: .utf8)
        return file.split(separator: "\n").first { !$0.hasPrefix("#") && !$0.isEmpty }.map(String.init) ?? ""
    }

    package static func minimal(interface: String = "", peer: String = "") throws -> String {
        try "[Interface]\nPrivateKey = \(key("client1.key"))\nAddress = 10.77.0.2/32\n\(interface)\n[Peer]\nPublicKey = \(key("server.pub"))\nAllowedIPs = 10.77.0.0/24\n\(peer)\n"
    }

    package static func containsFixtureSecret(_ text: String) throws -> Bool {
        for name in ["client1.key", "client2.key", "server.key", "psk1.key"] {
            let key = try key(name)
            guard let bytes = Data(base64Encoded: key) else { throw ByteCodecError.invalidEncoding }
            let hex = bytes.map { String(format: "%02x", $0) }.joined()
            let url = key.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").dropLast()
            if text.contains(key) || text.lowercased().contains(hex) || text.contains(url) {
                return true
            }
        }
        return false
    }

    package static func golden(_ name: String) throws -> [UInt8] {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Golden/\(name).uapi")
        return try Array(Data(contentsOf: path))
    }
}
