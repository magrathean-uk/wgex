// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXEngine

private struct CallbackDateTests {
    @Test(arguments: ["2025-10-25T05:26:40.000000005Z", "2025-10-25T05:26:40Z"])
    func `RFC3339 engine timestamps decode with optional nanoseconds`(_ value: String) throws {
        let date = try #require(CallbackBox.date(value))
        #expect(abs(date.timeIntervalSince1970 - 1_761_370_000) < 0.000001)
    }

    #if os(macOS)
        @Test func `typed descriptor linkage finds no NE descriptor on macOS`() {
            #expect(EngineLinkage.findUTunDescriptor() == -1)
        }
    #endif

    @Test func `invalid dates are rejected`() {
        #expect(CallbackBox.date(nil) == nil)
        #expect(CallbackBox.date("not a timestamp") == nil)
    }
}
