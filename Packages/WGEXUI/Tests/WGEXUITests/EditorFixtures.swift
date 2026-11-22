// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

package nonisolated enum EditorFixtures {
    package static var root: URL {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while url.path != "/" {
            let candidate = url.appendingPathComponent("Tests/Fixtures")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
            url.deleteLastPathComponent()
        }
        return url.appendingPathComponent("missing-fixtures")
    }

    package static func bytes(_ name: String = "ipv6-dual-stack") throws -> [UInt8] {
        try Array(Data(contentsOf: root.appendingPathComponent("conf/\(name).conf")))
    }

    package static func parsed(_ name: String = "ipv6-dual-stack") throws -> ParsedConfiguration {
        var input = try bytes(name)
        return try parseWgQuick(&input, name: "Home")
    }

    package static func profile() throws -> TunnelProfile {
        let parsed = try parsed()
        return parsed.profile
    }

    package static func containsSecret(_ text: String) throws -> Bool {
        let data = Data(text.utf8)
        for name in ["client1", "client2", "server", "psk1"] {
            let file = try Data(contentsOf: root.appendingPathComponent("keys/\(name).key"))
            let key = file.split(separator: 10).first { !$0.isEmpty && $0.first != 35 }.map { Data($0.filter { $0 != 13 }) }
            if let key, data.range(of: key) != nil {
                return true
            }
        }
        return false
    }
}
