// SPDX-License-Identifier: MIT
import Testing
@testable import WGEXCore

private struct PrefixArithmeticTests {
    @Test(arguments: ["0.0.0.0/0", "10.1.2.3/24", "::/0", "2001:db8::1234/64", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"])
    func `halves partition and merge to canonical parent`(_ text: String) throws {
        let range = try IPAddressRange(text)
        let (lower, upper) = try #require(range.halves())
        #expect(range.contains(lower) && range.contains(upper))
        #expect(!lower.overlaps(upper))
        #expect(IPAddressRange.merged([upper, lower, lower]) == [range.network])
    }

    @Test(arguments: ["192.0.2.1/32", "2001:db8::1/128"])
    func `host prefixes cannot split`(_ text: String) throws {
        #expect(try IPAddressRange(text).halves() == nil)
    }

    @Test
    func `merge removes overlaps and recursively joins siblings across families`() throws {
        let input = try ["10.0.0.1/26", "10.0.0.64/26", "10.0.0.128/25", "10.0.0.4/32", "::/1", "8000::/1"].map(IPAddressRange.init)
        #expect(IPAddressRange.merged(input).map(\.stringRepresentation) == ["10.0.0.0/24", "::/0"])
        #expect(IPAddressRange.merged([]).isEmpty)
    }

    @Test
    func `subtraction handles duplicate overlapping absent and covering exclusions`() throws {
        let ranges = try ["192.0.2.1/24", "192.0.2.0/25", "2001:db8::/126"].map(IPAddressRange.init)
        let excluded = try ["192.0.2.64/26", "192.0.2.64/27", "192.0.2.64/26", "203.0.113.0/24", "2001:db8::1/128"].map(IPAddressRange.init)
        let remaining = IPAddressRange.subtracting(ranges, excluding: excluded)
        #expect(remaining.map(\.stringRepresentation) == ["192.0.2.0/26", "192.0.2.128/25", "2001:db8::/128", "2001:db8::2/127"])
        #expect(IPAddressRange.subtracting(ranges, excluding: [.allIPv4, .allIPv6]).isEmpty)
        #expect(IPAddressRange.subtracting(ranges, excluding: []) == IPAddressRange.merged(ranges))
    }

    @Test
    func `private exclusion has exact size and leaves only disjoint public prefixes`() throws {
        let result = IPAddressRange.subtracting([.allIPv4, .allIPv4], excluding: IPAddressRange.privateIPv4)
        let size = result.reduce(UInt64(0)) { $0 + (UInt64(1) << (32 - $1.prefixLength)) }
        #expect(size == (UInt64(1) << 32) - (1 << 24) - (1 << 20) - (1 << 16) - (1 << 16))
        #expect(result.allSatisfy { prefix in !IPAddressRange.privateIPv4.contains { prefix.overlaps($0) } })
        #expect(zip(result, result.dropFirst()).allSatisfy { !$0.overlaps($1) })
        let host = try IPAddressRange("192.0.2.1")
        #expect(result.contains { $0.contains(host) })
    }
}
