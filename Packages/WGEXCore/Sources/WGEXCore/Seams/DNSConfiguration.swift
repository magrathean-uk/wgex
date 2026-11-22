// SPDX-License-Identifier: MIT

/// Resolver configuration the daemon publishes while a tunnel is up; the daemon's
/// `DNSConfigurator` turns it into SystemConfiguration keys and journals the change.
public struct DNSConfiguration: Codable, Sendable, Hashable {
    /// Resolver addresses.
    public var servers: [String]
    /// Search domains.
    public var searchDomains: [String]
    /// Match domains; empty means every query.
    public var matchDomains: [String]

    /// Creates a configuration.
    public init(servers: [String], searchDomains: [String], matchDomains: [String]) {
        self.servers = servers
        self.searchDomains = searchDomains
        self.matchDomains = matchDomains
    }
}
