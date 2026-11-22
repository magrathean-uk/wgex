// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct OrbMotionTests {
    @Test
    func `motion constants follow plan 06 §3`() {
        #expect(OrbMotion.connectSpring == .spring(duration: 0.5, bounce: 0.2))
        #expect(OrbMotion.rotationPeriod == 1.6)
        #expect(OrbMotion.glyphMorphDuration == 0.4)
        #expect(OrbMotion.glowBloomDuration == 0.6)
        #expect(OrbMotion.reassertCrossFade == .crossFade(duration: 0.25))
        #expect(OrbMotion.ringFade == .fade(duration: 0.3))
        #expect(OrbMotion.breathingPeriod == 12)
        #expect(OrbMotion.reducedCrossFade == .crossFade(duration: 0.2))
        #expect(OrbMotion.reducedDotStep == 1)
        #expect(ConnectionOrb.Size.allCases.map(\.diameter) == [96, 160, 220, 320])
    }

    @Test
    func `transitions map state-machine edges`() {
        #expect(OrbMotion.transition(from: .unprotected, to: .connecting, reduceMotion: false) == .spring(duration: 0.5, bounce: 0.2))
        #expect(OrbMotion.transition(from: .connecting, to: .protected, reduceMotion: false) == .snap)
        #expect(OrbMotion.transition(from: .protected, to: .reasserting, reduceMotion: false) == .crossFade(duration: 0.25))
        #expect(OrbMotion.transition(from: .protected, to: .unprotected, reduceMotion: false) == .fade(duration: 0.3))
        #expect(OrbMotion.transition(from: .protected, to: .blocked, reduceMotion: false) == .morph(duration: 0.4))
        #expect(OrbMotion.transition(from: nil, to: .unknown, reduceMotion: false) == .fade(duration: 0.3))
        #expect(OrbTransition.snap.animation == nil)
    }

    @Test(arguments: ProtectionVerdict.allCases)
    func `Reduce Motion turns every transition into a 0.2 s cross-fade`(_ verdict: ProtectionVerdict) {
        for old in ProtectionVerdict.allCases {
            #expect(OrbMotion.transition(from: old, to: verdict, reduceMotion: true) == .crossFade(duration: 0.2))
            #expect(!OrbMotion.blooms(from: old, to: verdict, reduceMotion: true))
        }
    }

    @Test
    func `feedback follows plan 06 §3`() throws {
        let cases = Dictionary(uniqueKeysWithValues: PresentationCases.all.map { ($0.name, $0.presentation) })
        let protected = try #require(cases["protected, idle"])
        let blocked = try #require(cases["blocked, active"])
        let systemStop = try #require(cases["unprotected, idle"])
        let userStop = try #require(cases["unprotected, user stop"])
        let unknown = try #require(cases["unknown, unspecified"])
        #expect(OrbMotion.feedback(from: .connecting, to: protected) == .success)
        #expect(OrbMotion.feedback(from: .reasserting, to: protected) == FeedbackKind.none)
        #expect(OrbMotion.feedback(from: .protected, to: blocked) == .warning)
        #expect(OrbMotion.feedback(from: .protected, to: systemStop) == .warning)
        #expect(OrbMotion.feedback(from: .protected, to: userStop) == FeedbackKind.none)
        #expect(OrbMotion.feedback(from: .protected, to: unknown) == FeedbackKind.none)
        #expect(OrbMotion.feedback(from: .protected, to: protected) == FeedbackKind.none)
    }

    @Test
    func `the glow blooms only on connect`() {
        #expect(OrbMotion.blooms(from: .connecting, to: .protected, reduceMotion: false))
        #expect(OrbMotion.blooms(from: .reasserting, to: .protected, reduceMotion: false))
        #expect(!OrbMotion.blooms(from: .unknown, to: .protected, reduceMotion: false))
        #expect(!OrbMotion.blooms(from: .connecting, to: .blocked, reduceMotion: false))
    }
}
