// SPDX-License-Identifier: MIT
import Foundation

/// Synthetic values only. Each of the 17 families has 20 distinct, deterministic seeds (340 leaks).
package enum RedactionCorpus {
    package struct Leak {
        package let value: String
        package let message: String
        package let exact: Bool
    }

    package static let leaks: [Leak] = (0 ..< 20).flatMap { index in
        let bytes = (0 ..< 32).map { UInt8(($0 * 17 + index * 29) % 256) }
        let key = Data(bytes).base64EncodedString()
        let urlKey = key.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let host = "endpoint-\(index).example.test"
        let sni = "sni-\(index).example.test"
        let path = "/ws/seed-\(index)/private-channel"
        let uuid = String(format: "01234567-89ab-4cde-8f01-%012d", index)
        let hex = bytes.reversed().map { String(format: "%02x", $0) }.joined()
        return [
            Leak(value: key, message: "PrivateKey = \(key)", exact: false),
            Leak(value: key, message: "PresharedKey = \(key)", exact: false),
            Leak(value: urlKey, message: "relay \(urlKey)", exact: false),
            Leak(value: String(urlKey.dropLast()), message: "relay \(urlKey.dropLast())", exact: false),
            Leak(value: path, message: "wss://\(host)\(path)", exact: true),
            Leak(value: sni, message: "TLS \(sni)", exact: true),
            Leak(value: host, message: "endpoint \(host):51820", exact: true),
            Leak(value: uuid, message: "session \(uuid)", exact: false),
            Leak(value: "private-profile-\(index)", message: "name private-profile-\(index)", exact: true),
            Leak(value: "private-ssid-\(index)", message: "wifi private-ssid-\(index)", exact: true),
            // The key crosses a physical 511-byte ring chunk boundary.
            Leak(value: key, message: String(repeating: ".", count: 490) + key, exact: true),
            // An unregistered base64url key split across a line break is caught by the pattern.
            Leak(value: String(urlKey.prefix(22)), message: "peer \(urlKey.prefix(22))\n\(urlKey.dropFirst(22))", exact: false),
            // A 12-character fragment of a registered secret is caught on its own.
            Leak(value: String(key.dropFirst(index).prefix(16)), message: "partial \(key.dropFirst(index).prefix(16)) end", exact: false),
            // UAPI-style hex keys are caught without registration.
            Leak(value: hex, message: "private_key=\(hex)", exact: false),
            Leak(value: "198.51.100.\(index + 1)", message: "endpoint 198.51.100.\(index + 1):51820", exact: false),
            Leak(value: "2001:db8::\(index + 1)", message: "endpoint [2001:db8::\(index + 1)]:51820", exact: false),
            Leak(value: "/tunnel-\(index)/upgrade", message: "{\"path\": \"/tunnel-\(index)/upgrade\"}", exact: false),
        ]
    }
}
