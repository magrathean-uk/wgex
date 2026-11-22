// SPDX-License-Identifier: MIT

/// Checks borrowed bytes before any public-field String is created.
package enum PublicFieldSafety {
    package static func isSearchDomain(_ value: String) -> Bool {
        (try? IPAddressRange(value)) == nil && (try? Endpoint(validatingHost: value, port: 1)) != nil
    }

    package static func containsKey(_ bytes: some Collection<UInt8>) -> Bool {
        KeyShape.contains(in: bytes)
    }
}
