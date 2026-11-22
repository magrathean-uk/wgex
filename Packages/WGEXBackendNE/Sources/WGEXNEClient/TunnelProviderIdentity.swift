// SPDX-License-Identifier: MIT

import WGEXCore

/// Identity of the packet tunnel extension configured by the app.
public enum TunnelProviderIdentity {
    /// `providerBundleIdentifier` for `NETunnelProviderProtocol`.
    public static var providerBundleIdentifier: String {
        BuildIdentifiers.current.tunnelExtension
    }
}
