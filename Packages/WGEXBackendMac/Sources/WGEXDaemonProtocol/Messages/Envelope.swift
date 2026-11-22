// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Every request travels in an envelope (02 §5). Secrets never do: they use
/// the separate ``SecretsWireLayout`` argument.
public struct Envelope: Codable, Sendable, Hashable {
    /// Protocol version written by this build. Version 7 adds cutover requests and status to the CAS protocol; version 8 adds
    /// the ADR-030 on-demand requests, the Wi-Fi report and its request event, and on-demand status.
    public static let currentProtocolVersion = 8

    /// Wire protocol version.
    public var protocolVersion: Int
    /// Correlates replies and logs.
    public var requestID: UUID
    /// `AuthorizationExternalForm` bytes for admin-right requests.
    public var authorization: Data?
    /// Optional generation fence for mutations (wire v2). Nil denotes a fresh user intent.
    public var expectedGeneration: Generation?
    /// The request.
    public var body: Request

    /// Creates an envelope at the current protocol version.
    public init(requestID: UUID = UUID(), authorization: Data? = nil, expectedGeneration: Generation? = nil, body: Request) {
        protocolVersion = Self.currentProtocolVersion
        self.requestID = requestID
        self.authorization = authorization
        self.expectedGeneration = expectedGeneration
        self.body = body
    }

    /// Decodes and checks the protocol version.
    public static func decode(_ data: Data) throws(DaemonError) -> Envelope {
        let envelope = try WireCodec.decode(Envelope.self, from: data)
        guard envelope.protocolVersion == currentProtocolVersion else {
            throw .unsupportedProtocolVersion(envelope.protocolVersion)
        }
        return envelope
    }

    /// Binary property-list encoding.
    public func encoded() throws(DaemonError) -> Data {
        try WireCodec.encode(self)
    }
}
