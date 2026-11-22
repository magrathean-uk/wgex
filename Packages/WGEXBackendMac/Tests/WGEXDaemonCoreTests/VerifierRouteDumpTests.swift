// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore

private struct VerifierRouteDumpTests {
    @Test
    func `dump2 fixture skips foreign ownership before interpreting its address layout`() throws {
        let hex = try NetworkPortHarness.fixture("RouteMessages/dump2-mixed-owners.hex")
        let bytes = try hex.split(whereSeparator: \.isWhitespace).map { try #require(UInt8($0, radix: 16)) }
        let messages = try RouteMessageCodec.parseDump(Data(bytes))
        #expect(messages.count == 2)
        #expect(messages.allSatisfy { $0.hasOwnershipMark && $0.pid == 0 && $0.sequence == 0 && $0.error == 0 })
    }
}
