// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXDiagnostics

private struct LogCategoryTests {
    @Test
    func `subsystem is the bundle identifier base`() {
        #expect(LogCategory.subsystem == BuildIdentifiers.current.base)
        #expect(Set(LogCategory.allCases.map(\.rawValue)).count == LogCategory.allCases.count)
    }
}
