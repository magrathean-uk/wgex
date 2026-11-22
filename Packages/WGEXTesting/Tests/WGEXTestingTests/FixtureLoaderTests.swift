// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXTesting

private struct FixtureLoaderTests {
    @Test
    func `the repository fixtures directory is found`() throws {
        let loader = try FixtureLoader.repository()
        #expect(loader.root.path.hasSuffix("/Tests/Fixtures"))
    }

    @Test
    func `paths cannot leave the fixtures directory`() throws {
        let loader = try FixtureLoader.repository()
        #expect(throws: FixtureLoader.LoadError.outsideFixtures("../README.md")) { _ = try loader.url("../README.md") }
        #expect(throws: FixtureLoader.LoadError.notFound("keys/does-not-exist")) { _ = try loader.data("keys/does-not-exist") }
    }
}
