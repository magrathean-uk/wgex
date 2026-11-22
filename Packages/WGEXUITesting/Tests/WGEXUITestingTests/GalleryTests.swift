// SPDX-License-Identifier: MIT

import SwiftUI
import Testing
import WGEXUI
import WGEXUITesting

private struct GalleryTests {
    @Test
    func `the fixtures cover every orb state except connecting variants`() {
        let verdicts = Set(PreviewFixtures.presentations.map(\.presentation.verdict))
        #expect(verdicts == Set(ProtectionVerdict.allCases))
        #expect(Set(PreviewFixtures.profileSummaries.compactMap(\.verdict)) == Set(ProtectionVerdict.allCases))
        #expect(PreviewFixtures.events.count <= 32)
        #expect(PreviewFixtures.downloadSeries.peak(endingAt: PreviewFixtures.referenceDate) == 2_400_000)
    }

    @Test
    func `galleries and trait presets build`() {
        _ = ConnectionOrbGallery().body
        _ = AnimatedOrbPreview().body
        _ = StatusComponentsGallery().body
        _ = SetupComponentsGallery().body
        _ = FormComponentsGallery().body
        _ = PreviewTraitsMatrix { StatusComponentsGallery() }.body
        #expect(PreviewTraits.all.count == 7)
        #expect(Set(PreviewTraits.all.map(\.id)).count == PreviewTraits.all.count)
        #expect(PreviewTraits.all.contains { $0.reduceMotion })
        #expect(PreviewTraits.all.contains { $0.reduceTransparency })
        #expect(PreviewTraits.all.contains { $0.increaseContrast && $0.dark })
        #expect(PreviewTraits.all.contains { $0.accessibilityText })
    }
}
