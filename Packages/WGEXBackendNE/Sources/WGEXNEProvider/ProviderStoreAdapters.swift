// SPDX-License-Identifier: MIT

import Foundation
import Security
import WGEXCore
import WGEXProfileStore

public struct AppGroupProfileLoader: ProviderProfileLoading {
    private let store: ProfileStore
    public init(container: URL) {
        store = ProfileStore(container: container)
    }

    public func load(_ id: UUID) async throws -> TunnelProfile {
        try await store.load(id)
    }
}

/// Keychain persistent references are resolved inside the extension; no secret strings are created.
public struct PersistentReferenceSecretLoader: ProviderSecretLoading {
    public init() {}
    public func load(for profile: TunnelProfile) async throws -> ParsedSecrets {
        let references = [profile.secrets.privateKey] + profile.secrets.presharedKeys.values
        var packed = Data()
        defer { packed.resetBytes(in: 0 ..< packed.count) }
        var ranges: [SecretRef: Range<Int>] = [:]
        for reference in references where ranges[reference] == nil {
            guard case let .keychain(persistentRef) = reference else { throw TunnelError.secretsUnavailable }
            let query: [CFString: Any] = [kSecValuePersistentRef: persistentRef, kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne]
            var result: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
                  var data = result as? Data else { throw TunnelError.secretsUnavailable }
            defer { data.resetBytes(in: 0 ..< data.count) }
            guard data.count == 32 else { throw TunnelError.secretsUnavailable }
            let start = packed.count
            packed.append(data); ranges[reference] = start ..< packed.count
        }
        return try ParsedSecrets(bytes: SecretBytes(wiping: &packed), references: ranges)
    }
}
