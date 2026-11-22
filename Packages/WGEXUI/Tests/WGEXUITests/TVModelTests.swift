// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
import WGEXTesting
import WGEXUI

@MainActor
internal struct TVModelTests {
    @Test(arguments: [
        TunnelPhase.idle,
        .preparing(Generation(rawValue: 1)),
        .configuring(Generation(rawValue: 1)),
        .active(Generation(rawValue: 1)),
        .reasserting(Generation(rawValue: 1), reason: .wake),
    ])
    internal func `impossible blocking is unknown`(_ phase: TunnelPhase) {
        var status = TunnelStatus.idle; status.phase = phase; status.protection = .blocked
        let view = TVConnectionState.presentation(status)
        #expect(view.verdict == .unknown)
        #expect(view.colour == .unknown)
        #expect(view.secondary.contains("does not match this device"))
    }

    @Test internal func `captive phase and protection are unknown`() {
        var status = TunnelStatus.idle
        status.protection = .captiveWindow(expires: .distantFuture)
        #expect(TVConnectionState.presentation(status).verdict == .unknown)
        status.protection = .protected
        status.phase = .captiveWindow(Generation(rawValue: 2), expires: .distantFuture)
        #expect(TVConnectionState.presentation(status).secondary.contains("does not match this device"))
    }

    @Test internal func `connected unsupported stale and events`() {
        var status = TunnelStatus.idle; status.phase = .active(Generation(rawValue: 1)); status.protection = .unsupported
        #expect(TVConnectionState.presentation(status).primary == "Connected")
        #expect(TVConnectionState.presentation(status, staleness: .stale(since: .distantPast)).verdict == .unknown)
        let event = TunnelEvent(date: .distantPast, kind: .protectionChanged(.blocked), generation: nil)
        #expect(TVConnectionState.events([event]).first?.kind == .protectionChanged(.unknown))
    }

    @Test internal func `defaults and policy`() {
        let settings = TVSettings()
        #expect(settings.alwaysOn && settings.allowLAN)
        let profile = settings.applying(to: TunnelProfile(name: "TV"))
        #expect(profile.onDemand == .always(exceptSSIDs: []))
        #expect(profile.protection.tv.enforceRoutes && profile.protection.tv.allowLAN)
        #expect(profile.protection.dnsPolicy == .tunnelAll)
    }

    @Test internal func `countdown expiry and renewal`() async {
        let clock = FakeClock()
        let receiver = TVFakePairingReceiver(value: TVPairingSnapshot(payload: "fixture"))
        let model = TVPairingModel(receiver: receiver, now: { clock.now.offset })
        await model.newCode()
        #expect(model.secondsRemaining == 120)
        clock.advance(by: .milliseconds(118_500)); await model.refresh()
        #expect(model.secondsRemaining == 2)
        clock.advance(by: .milliseconds(1500)); await model.refresh()
        #expect(model.snapshot.stage == .expired && model.secondsRemaining == 0)
        #expect(receiver.stopped)
        #expect(model.snapshot.payload.isEmpty)
        await model.newCode()
        #expect(model.secondsRemaining == 120 && !receiver.stopped)
        await model.stop()
        #expect(receiver.stopped && model.snapshot.stage == .stopped)
        receiver.value.stage = .expired
        await model.newCode(); await model.refresh()
        #expect(model.secondsRemaining == 0 && model.snapshot.stage == .expired)
    }

    @Test internal func `sas acceptance and attempt budget`() async {
        let receiver = TVFakePairingReceiver(value: TVPairingSnapshot(stage: .confirmSAS, sas: "123456", attempts: 3))
        let model = TVPairingModel(receiver: receiver)
        await model.newCode()
        #expect(model.canConfirm)
        await model.confirm(true)
        #expect(receiver.confirmations == [true])
        #expect(model.snapshot.stage == .receiving)
        receiver.value.stage = .failed; await model.refresh()
        #expect(model.snapshot.stage == .exhausted)
        #expect(!model.canConfirm)
    }

    @Test internal func `malformed SAS and decline and overwrite`() async {
        let receiver = TVFakePairingReceiver(value: TVPairingSnapshot(stage: .confirmSAS, sas: "12x456", attempts: 1))
        let model = TVPairingModel(receiver: receiver)
        await model.newCode(); await model.confirm(true)
        #expect(receiver.confirmations.isEmpty)
        receiver.value.sas = "654321"; await model.refresh(); await model.confirm(false)
        #expect(receiver.confirmations == [false])
        receiver.value.stage = .overwrite; await model.refresh(); await model.overwrite(false)
        #expect(model.snapshot.stage == .failed)
    }

    @Test internal func `paste routes to review and clears input`() throws {
        let model = TVPasteImportModel()
        model.text = Self.fixture
        model.prepare()
        let review = try #require(model.review)
        #expect(model.text.isEmpty)
        #expect(review.canImport)
        #expect(review.profile.protection.ipv6Policy == .blockOutside)
        var accepted = false
        #expect(review.confirm { _, _ in accepted = true })
        #expect(accepted)
        model.clear(); #expect(model.review == nil && model.text.isEmpty)
    }

    @Test internal func `invalid paste still routes to review`() throws {
        let model = TVPasteImportModel(); model.text = "not a configuration"; model.prepare()
        let review = try #require(model.review)
        #expect(!review.canImport && !review.errors.isEmpty)
        #expect(model.text.isEmpty)
    }

    @Test internal func `expiry rejects confirmation without A timer tick`() async {
        let clock = FakeClock()
        let receiver = TVFakePairingReceiver(value: TVPairingSnapshot(stage: .confirmSAS, sas: "123456", attempts: 1))
        let model = TVPairingModel(receiver: receiver, now: { clock.now.offset })
        await model.newCode()
        clock.advance(by: .seconds(120))
        await model.confirm(true)
        #expect(receiver.confirmations.isEmpty)
        #expect(model.snapshot.stage == .expired)
    }

    @Test internal func `fourth attempt cannot be accepted`() async {
        let receiver = TVFakePairingReceiver(value: TVPairingSnapshot(stage: .confirmSAS, sas: "123456", attempts: 4))
        let model = TVPairingModel(receiver: receiver)
        await model.newCode(); await model.confirm(true)
        #expect(receiver.confirmations.isEmpty)
        #expect(!model.canConfirm)
    }

    private static var fixture: String {
        (try? FixtureLoader.repository().text("conf/single-peer-full-tunnel.conf")) ?? ""
    }
}
