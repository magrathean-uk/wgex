// SPDX-License-Identifier: MIT

import Testing
import WGEXProfileStore

private struct ProfileStoreSchemaTests {
    @Test
    func `document versions distinguish envelope and journal`() {
        #expect(ProfileStoreSchema.profileDocumentVersion == 3)
        #expect(ProfileStoreSchema.journalVersion == 1)
    }
}
