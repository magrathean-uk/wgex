// SPDX-License-Identifier: MIT
import Foundation
import Network

/// A peer endpoint: host name or literal address plus port.
public struct Endpoint: Codable, Sendable, Hashable {
    public var host: String
    public var port: UInt16

    /// Trusted package construction, including invalid values used by validation tests.
    package init(host: String, port: UInt16) {
        self.host = host; self.port = port
    }

    public init?(validating text: String) {
        guard let endpoint = try? Endpoint(text) else { return nil }
        self = endpoint
    }

    /// Parses `host:port` or `[IPv6]:port` without resolving a hostname.
    public init(_ text: String) throws(ConfigurationError) {
        let hostPart: String
        let portPart: Substring
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]"), text.index(after: close) < text.endIndex,
                  text[text.index(after: close)] == ":"
            else { throw .invalidEndpoint }
            hostPart = String(text[text.index(after: text.startIndex) ..< close])
            guard IPv6Address(hostPart) != nil else { throw .invalidEndpoint }
            portPart = text[text.index(close, offsetBy: 2)...]
        } else {
            let parts = text.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { throw .invalidEndpoint }
            hostPart = String(parts[0]); portPart = parts[1]
        }
        guard !portPart.isEmpty, portPart.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              let number = UInt16(portPart), number > 0
        else { throw .invalidPort }
        try self.init(validatingHost: hostPart, port: number)
    }

    public init(validatingHost host: String, port: UInt16) throws(ConfigurationError) {
        self.host = host; self.port = port
        try validate()
    }

    public func validate() throws(ConfigurationError) {
        guard port > 0 else { throw .invalidPort }
        guard !host.contains("%"), !host.isEmpty else { throw .invalidEndpoint }
        if IPAddressRange.isStrictLiteral(host) {
            return
        }
        guard host.utf8.count <= 253, !host.contains(":"),
              !host.utf8.allSatisfy({ (48 ... 57).contains($0) || $0 == 46 })
        else { throw .invalidEndpoint }
        let labels = (host.hasSuffix(".") ? String(host.dropLast()) : host)
            .split(separator: ".", omittingEmptySubsequences: false)
        guard let last = labels.last,
              !last.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              !last.lowercased().hasPrefix("0x"),
              labels.allSatisfy({ label in
                  (1 ... 63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
                      label.utf8
                      .allSatisfy { (65 ... 90).contains($0) || (97 ... 122).contains($0) || (48 ... 57).contains($0) || $0 == 45 }
              }) else { throw .invalidEndpoint }
    }

    public var stringRepresentation: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(validatingHost: container.decode(String.self, forKey: .host), port: container.decode(UInt16.self, forKey: .port))
    }
}
