// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXProfileStore

/// App-only mapping to SecretStore accounts. Never encoded or sent to the daemon.
/// The importing app supplies these account identities; the CLI has no store.
public struct AppSecretReferences: Sendable {
    public let privateKey: SecretID
    public let presharedKeys: [PublicKey: SecretID]
    public let carrierCredentials: [TransportID: SecretID]

    public init(privateKey: SecretID, presharedKeys: [PublicKey: SecretID] = [:], carrierCredentials: [TransportID: SecretID] = [:]) {
        self.privateKey = privateKey
        self.presharedKeys = presharedKeys
        self.carrierCredentials = carrierCredentials
    }

    package func wireBytes(from store: any SecretStore, profileID: UUID) async throws -> SecretBytes {
        let accounts = [privateKey] + Array(presharedKeys.values) + Array(carrierCredentials.values)
        guard accounts.allSatisfy({ $0.profileID == profileID }), privateKey.kind == .privateKey,
              presharedKeys.values.allSatisfy({ $0.kind == .presharedKey }),
              carrierCredentials.values.allSatisfy({ $0.kind == .carrierCredential })
        else { throw DaemonError.secretsUnavailable }
        let key = try await store.load(privateKey)
        var writer = try SecretsWireWriter(privateKey: key)
        for (peer, account) in presharedKeys.sorted(by: { $0.key.base64 < $1.key.base64 }) {
            let psk = try await store.load(account)
            try writer.appendPresharedKey(psk, for: peer)
        }
        for (transport, account) in carrierCredentials.sorted(by: { $0.key.rawValue.uuidString < $1.key.rawValue.uuidString }) {
            let credential = try await store.load(account)
            try writer.appendCarrierCredential(credential, for: transport)
        }
        return try writer.finish()
    }
}
