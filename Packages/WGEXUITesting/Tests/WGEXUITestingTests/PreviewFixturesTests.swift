// SPDX-License-Identifier: MIT

import Testing
import WGEXCore
import WGEXTesting
import WGEXUITesting

private struct PreviewFixturesTests {
    @Test
    func `every phase has a preview status`() {
        #expect(PreviewFixtures.statuses.count == 8)
        #expect(Set(PreviewFixtures.statuses.map(\.id)).count == PreviewFixtures.statuses.count)
    }

    @Test
    func `fake backends start from the requested status`() async throws {
        let active = try #require(PreviewFixtures.statuses.first { $0.id == "Active" })
        let backend = await PreviewFixtures.backend(showing: active.status)
        #expect(backend.currentStatus.phase == active.status.phase)
        #expect(backend.installedProfiles.map(\.id) == [PreviewFixtures.profile.id])
        let controller = PreviewFixtures.serviceController()
        var states = controller.state.makeAsyncIterator()
        #expect(await states.next() == .requiresApproval)
    }
}
