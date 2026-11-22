// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

/// Compatibility name for the shared prefix type. Arithmetic and validation live in WGEXCore.
public typealias CIDRBlock = WGEXCore.IPAddressRange

public extension IPAddressRange {
    /// Compatibility parser; maps shared validation failures to field messages.
    nonisolated init(parsing text: String) throws(CIDRParseError) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw .empty }
        do { try self.init(trimmed) }
        catch {
            let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
            if parts.count == 2, let address = try? IPAddressRange(String(parts[0])) {
                throw .invalidPrefix(maximum: address.isIPv6 ? 128 : 32)
            }
            throw .invalidAddress
        }
    }
}

/// Why a prefix did not parse.
public nonisolated enum CIDRParseError: Error, Sendable, Hashable {
    /// Nothing was entered.
    case empty
    /// The address is not an IPv4 or IPv6 literal.
    case invalidAddress
    /// The prefix length is out of range.
    case invalidPrefix(maximum: Int)

    /// Field message.
    public var message: String {
        switch self {
        case .empty: "Enter an address"
        case .invalidAddress: "Invalid address"
        case let .invalidPrefix(maximum): maximum == 32 ? "Prefix must be 0–32 for IPv4" : "Prefix must be 0–128 for IPv6"
        }
    }
}
