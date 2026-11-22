// SPDX-License-Identifier: MIT

/// A route the daemon installs through the tunnel interface; the daemon's `RouteTable`
/// resolves the destination string into an `IPAddressRange` before programming the kernel.
public struct RouteSpec: Codable, Sendable, Hashable {
    /// Destination address text, for example `0.0.0.0` or `::`.
    public var destination: String
    /// Prefix length.
    public var prefixLength: UInt8
    /// Interface the route points at, for example `utun7`.
    public var interfaceName: String

    /// Creates a route.
    public init(destination: String, prefixLength: UInt8, interfaceName: String) {
        self.destination = destination
        self.prefixLength = prefixLength
        self.interfaceName = interfaceName
    }
}
