// SPDX-License-Identifier: MIT
import WGEXCore

public enum PairingService {
    public static let bonjourType = "_wgex-pair._tcp"
}

public protocol PairingAdvertising: Sendable {
    func start() async throws
    func stop() async
}

public struct NoPairingAdvertisement: PairingAdvertising {
    public init() {}
    public func start() async throws {}
    public func stop() async {}
}

/// The store boundary receives uniquely owned parsed secrets only after acceptance.
public protocol PairingProfileSink: Sendable {
    func contains(publicKey: PublicKey) async throws -> Bool
    func confirmOverwrite(_ profile: TunnelProfile) async -> Bool
    func store(_ configuration: consuming ParsedConfiguration) async throws
}
