// SPDX-License-Identifier: MIT

import Foundation

public enum MarkerWire {
    public static func validNonce(_ nonce: String) -> Bool {
        (1 ... 63).contains(nonce.utf8.count) && nonce.utf8.allSatisfy { (48 ... 57).contains($0) || (97 ... 122).contains($0) || $0 == 45 }
    }

    /// A unique name resolved through the system resolver, distinct from direct marker DNS.
    public static func systemResolverName(nonce: String) throws -> String {
        guard validNonce(nonce + "-system") else { throw ProbeError.configuration("system resolver nonce") }
        return nonce + "-system.leak.wgex.test"
    }

    public static func dns(nonce: String, format: MarkerFormat, ipv6: Bool) throws -> Data {
        guard validNonce(nonce) else { throw ProbeError.configuration("nonce") }
        var bytes: [UInt8] = [0x57, 0x47, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in [nonce, format.rawValue, "wgex", "test"] {
            bytes.append(UInt8(label.utf8.count)); bytes += label.utf8
        }
        bytes += [0, 0, ipv6 ? 28 : 1, 0, 1]
        return Data(bytes)
    }

    public static func http(nonce: String, format: MarkerFormat, host: String) throws -> Data {
        guard validNonce(nonce), !host.isEmpty, host.utf8.allSatisfy({ (33 ... 126).contains($0) }) else {
            throw ProbeError.configuration("HTTP marker")
        }
        return Data("GET /\(format.rawValue)/\(nonce) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8)
    }

    public static func udp(nonce: String) throws -> Data {
        guard validNonce(nonce) else { throw ProbeError.configuration("nonce") }
        return Data("WGEXLEAK \(nonce)".utf8)
    }

    /// Only complete, uncompressed single-question marker DNS packets are accepted.
    public static func dnsNonce(_ data: Data) -> String? {
        let bytes = Array(data)
        guard bytes.count >= 17, bytes[2] & 0x80 == 0, bytes[4] == 0, bytes[5] == 1 else { return nil }
        var cursor = 12, labels: [String] = []
        while cursor < bytes.count {
            let length = Int(bytes[cursor]); cursor += 1
            if length == 0 {
                break
            }
            guard length <= 63, cursor + length <= bytes.count else { return nil }
            labels.append(String(decoding: bytes[cursor ..< cursor + length], as: UTF8.self)); cursor += length
        }
        guard labels.count == 4, ["marker", "leak"].contains(labels[1]), labels[2...] == ["wgex", "test"],
              validNonce(labels[0]), cursor + 4 == bytes.count, bytes[cursor] == 0, [1, 28].contains(bytes[cursor + 1]),
              bytes[cursor + 2] == 0, bytes[cursor + 3] == 1
        else { return nil }
        return labels[0]
    }

    public static func nonce(_ data: Data) -> (String, MarkerProtocol)? {
        if let nonce = dnsNonce(data) {
            return (nonce, .dns)
        }
        let text = String(decoding: data, as: UTF8.self)
        if text.hasPrefix("WGEXLEAK "), let nonce = text.dropFirst(9).split(whereSeparator: \.isWhitespace).first,
           validNonce(String(nonce))
        {
            return (String(nonce), .udp)
        }
        if let first = text.components(separatedBy: "\r\n").first {
            let words = first.split(separator: " ")
            if words.count == 3, words[0] == "GET", words[2] == "HTTP/1.1" {
                let path = words[1].split(separator: "/")
                if path.count == 2, ["marker", "leak"].contains(path[0]), validNonce(String(path[1])) {
                    return (String(path[1]), .http)
                }
            }
        }
        return nil
    }
}
