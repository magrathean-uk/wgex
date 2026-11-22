// SPDX-License-Identifier: MIT
import Foundation

/// References only; secret material is never part of the Codable profile.
public enum SecretRef: Codable, Sendable, Hashable {
    case keychain(persistentRef: Data)
    case daemonStore(id: UUID)
}

public struct SecretReferences: Codable, Sendable, Hashable {
    public var privateKey: SecretRef // .keychain(persistentRef) | .daemonStore(id)
    public var presharedKeys: [PublicKey: SecretRef]
    public var carrierCredentials: [TransportID: SecretRef]

    public init(
        privateKey: SecretRef, presharedKeys: [PublicKey: SecretRef] = [:], carrierCredentials: [TransportID: SecretRef] = [:],
    ) {
        self.privateKey = privateKey; self.presharedKeys = presharedKeys; self.carrierCredentials = carrierCredentials
    }

    /// String dictionary keys keep sorted-key JSON deterministic for multiple references.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(privateKey, forKey: .privateKey)
        try container.encode(Dictionary(uniqueKeysWithValues: presharedKeys.map { ($0.key.base64, $0.value) }), forKey: .presharedKeys)
        try container.encode(
            Dictionary(uniqueKeysWithValues: carrierCredentials.map { ($0.key.rawValue.uuidString, $0.value) }),
            forKey: .carrierCredentials,
        )
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        privateKey = try container.decode(SecretRef.self, forKey: .privateKey)
        presharedKeys = [:]; carrierCredentials = [:]
        for (key, value) in try container.decode([String: SecretRef].self, forKey: .presharedKeys) {
            let parsed = try PublicKey(base64: key)
            guard presharedKeys.updateValue(value, forKey: parsed) == nil else { throw ConfigurationError.invalidSecretReference }
        }
        for (key, value) in try container.decode([String: SecretRef].self, forKey: .carrierCredentials) {
            guard let id = UUID(uuidString: key), carrierCredentials.updateValue(value, forKey: TransportID(rawValue: id)) == nil
            else { throw ConfigurationError.invalidSecretReference }
        }
    }

    private enum CodingKeys: String, CodingKey { case privateKey, presharedKeys, carrierCredentials }
}
