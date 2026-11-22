// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonCore

/// In-memory configd values and resolver text; never reads or writes host DNS.
public actor FakeDNSSession: DNSSession {
    /// Current synthetic DNS values indexed by configd key.
    public private(set) var values: [String: SyntheticDNSValue] = [:]
    /// Ordered fixture mutation names.
    public private(set) var operations: [String] = []
    /// Resolver text returned to precedence checks.
    public var listing: String
    /// Creates the inert fixture with explicitly supplied state.
    public init(listing: String = "") {
        self.listing = listing
    }

    /// Replaces the fixture resolver listing returned by resolverListing().
    public func setListing(_ listing: String) {
        self.listing = listing
    }

    /// Reads a value from the fixture state.
    public func read(key: String) -> SyntheticDNSValue? {
        values[key]
    }

    /// Removes only the selected fixture key.
    public func remove(key: String) {
        operations.append("remove"); values.removeValue(forKey: key)
    }

    /// Adds the supplied value to the fixture configd dictionary.
    public func addTemporary(key: String, value: SyntheticDNSValue) {
        operations.append("addTemporary"); values[key] = value
    }

    /// Returns the supplied fixture resolver text.
    public func resolverListing() -> String {
        listing
    }
}
