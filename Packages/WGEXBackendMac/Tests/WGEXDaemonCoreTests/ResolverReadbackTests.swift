// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXDaemonCore

private struct ResolverReadbackTests {
    @Test(arguments: ["group 1464288600", "group = 1464288600"])
    func `numeric resolver group equality survives pfctl readback`(group: String) {
        let rendered = "pass out quick on en0 inet proto udp from any to 192.0.2.53 port 53 user 0 group = 1464288600 keep state label \"wgex-resolver\"\n"
        let actual = "pass out quick on en0 inet proto udp from any to 192.0.2.53 port = 53 user = 0 \(group) keep state label \"wgex-resolver\"\n"
        #expect(PacketFilterReadback.matches(actual, rendered: rendered))
        #expect(!PacketFilterReadback.matches(actual.replacingOccurrences(of: group, with: "group != 1464288600"), rendered: rendered))
        #expect(!PacketFilterReadback.matches(actual.replacingOccurrences(of: "1464288600", with: "0"), rendered: rendered))
    }
}
