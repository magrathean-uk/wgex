// SPDX-License-Identifier: MIT

import CryptoKit
import Foundation
import Network

public enum ProbeError: Error, Sendable {
    case configuration(String)
    case socket(Int32)
    case selftest
}

public enum MarkerScope: String, Codable, Sendable { case inTunnel = "in_tunnel", outsideTunnel = "outside_tunnel", gateway }
public enum MarkerProtocol: String, Codable, Sendable, CaseIterable { case dns, http, udp, tcp }
public enum MarkerFormat: String, Codable, Sendable { case marker, leak }
public enum ObservationKind: String, Codable, Sendable { case sent, response, received, failure }

public struct ProbeTarget: Codable, Sendable, Equatable {
    public let address: String
    public let scope: MarkerScope
    public let dnsPort: UInt16
    public let httpPort: UInt16
    public let udpPort: UInt16
    public let resolver: String?
    public let httpHost: String?
    public let allowedLAN: Bool

    public init(
        address: String, scope: MarkerScope, dnsPort: UInt16 = 5354, httpPort: UInt16 = 8088,
        udpPort: UInt16 = 8088, resolver: String? = nil, httpHost: String? = nil, allowedLAN: Bool = false,
    ) {
        self.address = address; self.scope = scope; self.dnsPort = dnsPort; self.httpPort = httpPort; self.udpPort = udpPort
        self.resolver = resolver; self.httpHost = httpHost; self.allowedLAN = allowedLAN
    }

    public func validate() throws {
        guard Self.isLiteral(address), resolver.map(Self.isLiteral) != false, dnsPort > 0, httpPort > 0, udpPort > 0,
              httpHost.map({ !$0.isEmpty && $0.utf8.allSatisfy { (33 ... 126).contains($0) } }) != false
        else { throw ProbeError.configuration("numeric address, nonzero ports and safe HTTP host required") }
    }

    public static func isLiteral(_ address: String) -> Bool {
        !address.contains("%") && (IPv4Address(address) != nil || IPv6Address(address) != nil)
    }

    public var family: String {
        address.contains(":") ? "ipv6" : "ipv4"
    }
}

public struct ProbeConfiguration: Codable, Sendable, Equatable {
    public let targets: [ProbeTarget]
    public let format: MarkerFormat
    public let intervalMilliseconds: Int
    /// Optional TCP connect/send budget for controlled high latency paths.
    public let tcpTimeoutMilliseconds: Int?

    public init(targets: [ProbeTarget], format: MarkerFormat = .marker, tcpTimeoutMilliseconds: Int? = nil) {
        self.targets = targets; self.format = format; intervalMilliseconds = 500
        self.tcpTimeoutMilliseconds = tcpTimeoutMilliseconds
    }

    public func validate() throws {
        guard !targets.isEmpty, intervalMilliseconds == 500 else { throw ProbeError.configuration("targets and 500 ms interval required") }
        if let tcpTimeoutMilliseconds {
            guard (100 ... 5000).contains(tcpTimeoutMilliseconds) else { throw ProbeError.configuration("TCP budget") }
        }
        for target in targets {
            try target.validate()
        }
    }
}

public struct MarkerObservation: Codable, Sendable, Equatable {
    public let timestamp: Double
    public let nonce: String
    public let kind: ObservationKind
    public let scope: MarkerScope
    public let family: String
    public let proto: MarkerProtocol
    public let address: String
    public let port: UInt16
    public let allowedLAN: Bool
    public let detail: String?

    public init(
        timestamp: Double = Date().timeIntervalSince1970, nonce: String, kind: ObservationKind, scope: MarkerScope,
        family: String, proto: MarkerProtocol, address: String, port: UInt16, allowedLAN: Bool = false, detail: String? = nil,
    ) {
        self.timestamp = timestamp; self.nonce = nonce; self.kind = kind; self.scope = scope; self.family = family
        self.proto = proto; self.address = address; self.port = port; self.allowedLAN = allowedLAN; self.detail = detail
    }
}

/// Legacy receiver completeness is retained for decoding; the verdict computes coverage from receiver lifetimes and controls.
public struct ObservationWindow: Codable, Sendable, Equatable {
    public let state: String
    public let start: Double
    public let end: Double
    public let receiversComplete: Bool
    public let allowLAN: Bool
    public let requiredFamilies: [String]

    public init(
        state: String,
        start: Double,
        end: Double,
        receiversComplete: Bool,
        allowLAN: Bool = false,
        requiredFamilies: [String] = ["ipv4", "ipv6"],
    ) {
        self.state = state; self.start = start; self.end = end; self.receiversComplete = receiversComplete
        self.allowLAN = allowLAN; self.requiredFamilies = requiredFamilies
    }
}

public struct ProbeRunRecord: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let nonce: String
    public let configuration: ProbeConfiguration
    public let configurationSHA256: String
    public var observations: [MarkerObservation]
    public var windows: [ObservationWindow]
    public var inputHashes: [String: String]

    public init(
        nonce: String,
        configuration: ProbeConfiguration,
        observations: [MarkerObservation] = [],
        windows: [ObservationWindow] = [],
        inputHashes: [String: String] = [:],
    ) throws {
        guard MarkerWire.validNonce(nonce) else { throw ProbeError.configuration("nonce") }
        try configuration.validate()
        schemaVersion = 1; self.nonce = nonce; self.configuration = configuration
        configurationSHA256 = try Self.hash(Self.canonicalData(configuration))
        self.observations = observations; self.windows = windows; self.inputHashes = inputHashes
    }

    public static func canonicalData(_ value: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    public static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
