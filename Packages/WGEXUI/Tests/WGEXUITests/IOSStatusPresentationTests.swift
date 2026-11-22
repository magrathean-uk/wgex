// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct IOSStatusPresentationTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test(arguments: [
        TunnelPhase.preparing(Generation(rawValue: 1)),
        .configuring(Generation(rawValue: 1)),
        .reasserting(Generation(rawValue: 1), reason: .pathChanged),
    ])
    func `transitions keep mac v2 neutral colour and existing consequences`(_ phase: TunnelPhase) {
        var status = TunnelStatus.idle
        status.phase = phase
        let value = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        #expect(value.protection.colour == .unknown)
        #expect(value.protection.action == (value.protection.verdict == .reasserting ? .disconnect : .cancel))
        #expect(!value.protection.secondary.isEmpty)
    }

    @Test func `unmeasured rates never become invented zeroes`() {
        var status = TunnelStatus.idle
        status.health = TunnelHealth(level: .healthy, lastHandshake: nil, rxRate: 99, txRate: 33)
        let value = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        #expect(value.handshake == .unavailable)
        #expect(value.download == .unavailable)
        #expect(value.upload == .unavailable)
    }

    @Test func `measured handshake and stale evidence stay distinct`() {
        var status = TunnelStatus.idle
        status.phase = .active(Generation(rawValue: 1))
        status.protection = .protected
        status.health.lastHandshake = now.addingTimeInterval(-30)
        let fresh = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        #expect(fresh.handshake == .age(since: now.addingTimeInterval(-30), now: now))
        let stale = IOSStatusPresentation(
            status: status,
            userInitiated: false,
            now: now,
            staleness: .stale(since: now.addingTimeInterval(-60)),
        )
        #expect(stale.protection.isStale)
        #expect(stale.protection.colour == .unknown)
        #expect(stale.protection.verdict == .stale)
        #expect(stale.protection.secondary == UserStrings.staleReport(UIFormat.ago(now.addingTimeInterval(-60), now: now)))
        #expect(stale.handshake == fresh.handshake)
    }

    @Test func `handshake ages with injected time and sheet shares the single peer measurement`() {
        var status = TunnelStatus.idle
        status.health.lastHandshake = now.addingTimeInterval(-30)
        let first = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        let later = IOSStatusPresentation(status: status, userInitiated: false, now: now.addingTimeInterval(60))
        #expect(first.handshake.text == UIFormat.ago(now.addingTimeInterval(-30), now: now))
        #expect(later.handshake.text == UIFormat.ago(now.addingTimeInterval(-30), now: now.addingTimeInterval(60)))
        #expect(first.handshake.text != later.handshake.text)
        #expect(first.peerHandshakeText(peerCount: 1) == first.handshake.text)
        #expect(later.peerHandshakeText(peerCount: 1) == later.handshake.text)
        #expect(later.peerHandshakeText(peerCount: 2) == "Not sampled per peer")
        let unknown = IOSStatusPresentation(status: .idle, userInitiated: false, now: now)
        #expect(unknown.peerHandshakeText(peerCount: 1) == "Unavailable")
    }

    private func sample(_ peers: [PeerStatistics]) -> TunnelStatistics {
        TunnelStatistics(generation: 1, sampledAt: now, interfaceName: "utun4", listenPort: nil, peers: peers)
    }

    private func peer(_ key: PublicKey, handshake: Date?, rx: UInt64, tx: UInt64) -> PeerStatistics {
        PeerStatistics(publicKey: key, endpoint: nil, lastHandshake: handshake, rxBytes: rx, txBytes: tx, persistentKeepalive: nil)
    }

    @Test func `live counters total every peer and format as decimal bytes`() throws {
        let first = try PrivateKey.generate().publicKey(), second = try PrivateKey.generate().publicKey()
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample([
            peer(first, handshake: now.addingTimeInterval(-90), rx: 1500, tx: 999),
            peer(second, handshake: now.addingTimeInterval(-5), rx: 2_000_000, tx: 1),
        ]))
        #expect(value.received == .bytes(2_001_500))
        #expect(value.sent == .bytes(1000))
        #expect(value.received.text == UIFormat.bytes(2_001_500))
        #expect(value.sent.text == UIFormat.bytes(1000))
        // The latest handshake is the most recent of any peer.
        #expect(value.handshake == .age(since: now.addingTimeInterval(-5), now: now))
        #expect(value.handshake.text == UIFormat.ago(now.addingTimeInterval(-5), now: now))
        // Rates are still not invented from totals.
        #expect(value.download == .unavailable)
        #expect(value.upload == .unavailable)
    }

    @Test func `counters without a sample are unavailable, never zero`() {
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now)
        #expect(value.received == .unavailable)
        #expect(value.sent == .unavailable)
        #expect(value.received.text == MacStrings.unavailable)
        let empty = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample([]))
        #expect(empty.received == .bytes(0))
        #expect(empty.received.text == UIFormat.bytes(0))
    }

    @Test func `a sample without any handshake says so instead of unavailable`() throws {
        let key = try PrivateKey.generate().publicKey()
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample([
            peer(key, handshake: nil, rx: 0, tx: 148),
        ]))
        #expect(value.handshake == .text(IOSStatusPresentation.noHandshake))
        #expect(value.handshake.text == "No handshake yet")
        let fields = value.peerCounters(key, peerCount: 1)
        #expect(fields.map(\.title) == ["Latest handshake", "Data received", "Data sent"])
        #expect(fields.map(\.value) == ["No handshake yet", UIFormat.bytes(0), UIFormat.bytes(148)])
    }

    @Test func `peer counters use that peer's sample and age with the clock`() throws {
        let first = try PrivateKey.generate().publicKey(), second = try PrivateKey.generate().publicKey()
        let peers = [
            peer(first, handshake: now.addingTimeInterval(-30), rx: 10, tx: 20),
            peer(second, handshake: now.addingTimeInterval(-3600), rx: 30, tx: 40),
        ]
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample(peers))
        #expect(value.peerCounters(second, peerCount: 2).map(\.value) == [
            UIFormat.ago(now.addingTimeInterval(-3600), now: now), UIFormat.bytes(30), UIFormat.bytes(40),
        ])
        let later = IOSStatusPresentation(status: .idle, userInitiated: false, now: now.addingTimeInterval(60), statistics: sample(peers))
        #expect(later.peerCounters(first, peerCount: 2).first?.value == UIFormat.ago(
            now.addingTimeInterval(-30),
            now: now.addingTimeInterval(60),
        ))
        #expect(later.peerCounters(first, peerCount: 2).first?.value != value.peerCounters(first, peerCount: 2).first?.value)
        #expect(Set(value.peerCounters(first, peerCount: 2).map(\.id)).isDisjoint(with: value.peerCounters(second, peerCount: 2).map(\.id)))
    }

    @Test func `a peer missing from the sample or no sample shows unavailable counters`() throws {
        let listed = try PrivateKey.generate().publicKey(), missing = try PrivateKey.generate().publicKey()
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample([
            peer(listed, handshake: now, rx: 1, tx: 1),
        ]))
        #expect(value.peerCounters(missing, peerCount: 2).map(\.value) == ["Not sampled per peer", "Unavailable", "Unavailable"])
        let none = IOSStatusPresentation(status: .idle, userInitiated: false, now: now)
        #expect(none.peerCounters(missing, peerCount: 1).map(\.value) == ["Unavailable", "Unavailable", "Unavailable"])
    }

    @Test func `counter totals saturate instead of trapping`() throws {
        let first = try PrivateKey.generate().publicKey(), second = try PrivateKey.generate().publicKey()
        let value = IOSStatusPresentation(status: .idle, userInitiated: false, now: now, statistics: sample([
            peer(first, handshake: nil, rx: .max, tx: 1),
            peer(second, handshake: nil, rx: 1, tx: 1),
        ]))
        #expect(value.received == .bytes(.max))
        #expect(value.sent == .bytes(2))
    }

    @Test func `iOS rejects a Mac captive window protection claim`() {
        var status = TunnelStatus.idle
        status.phase = .captiveWindow(Generation(rawValue: 1), expires: now.addingTimeInterval(60))
        status.protection = .captiveWindow(expires: now.addingTimeInterval(60))
        let value = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        #expect(value.protection.verdict == .unknown)
    }

    @Test func `unknown protection explains extension unavailable`() {
        var status = TunnelStatus.idle
        status.phase = .active(Generation(rawValue: 1))
        status.protection = .unknown
        let value = IOSStatusPresentation(status: status, userInitiated: false, now: now)
        #expect(value.protection.secondary == MacStrings.vpnExtensionStatusIsUnavailable)
    }

    @Test func `profile fields include public configuration and every peer`() {
        var profile = TunnelProfile(name: "Fixture")
        profile.peers = [
            PeerConfiguration(publicKey: profile.interface.publicKey, allowedIPs: []),
            PeerConfiguration(publicKey: profile.interface.publicKey, allowedIPs: []),
        ]
        let fields = IOSStatusPresentation.details(profile)
        #expect(fields.filter { $0.id.hasSuffix(".publicKey") }.count == 2)
        #expect(fields.contains { $0.title == "Public key" && $0.value == profile.interface.publicKey.base64 })
        #expect(fields.contains { $0.title == "MTU" && $0.value == "Automatic" })
        #expect(fields.contains { $0.title == "DNS" && $0.value == "Not configured" })
        #expect(fields.contains { $0.id == "peer.0.keepalive" && $0.value == "Off" })
        #expect(fields.filter { $0.id.hasPrefix("peer.0.") }.map(\.title) == [
            "Peer 1 endpoint", "Peer 1 allowed IPs", "Peer 1 persistent keepalive", "Peer 1 public key",
        ])
        #expect(fields.filter { $0.id.hasPrefix("peer.1.") }.map(\.title) == [
            "Peer 2 endpoint", "Peer 2 allowed IPs", "Peer 2 persistent keepalive", "Peer 2 public key",
        ])
        #expect(fields.filter { $0.id.hasSuffix(".allowedIPs") }.map(\.value) == ["None", "None"])
        #expect(fields.first { $0.id == "addresses" }?.value == "None")
        #expect(Set(fields.map(\.id)).count == fields.count)
        #expect(!fields.contains { $0.title.lowercased().contains("private") || $0.title.lowercased().contains("preshared") })
    }

    @Test func `protection fields describe configuration without promising enforcement`() {
        var policy = ProtectionPolicy(ipv6Policy: .tunnel)
        policy.ios.includeAllNetworks = true
        policy.ios.excludeLocalNetworks = false
        let fields = IOSStatusPresentation.protectionFields(policy: policy, onDemand: .always(exceptSSIDs: ["Home"]))
        #expect(fields.map(\.value) == ["On", "Off", "Always except trusted networks"])
        #expect(IOSStatusPresentation.protectionFields(policy: policy, onDemand: .off).last?.value == "Off")
        #expect(IOSStatusPresentation.protectionFields(policy: policy, onDemand: .wifiOnly(exceptSSIDs: [])).last?.value == "Wi-Fi only")
        #expect(IOSStatusPresentation.protectionFields(policy: policy, onDemand: .wifiOnly(exceptSSIDs: ["Home"])).last?.value ==
            "Wi-Fi only except trusted networks")
        #expect(IOSStatusPresentation.protectionFields(policy: policy, onDemand: .cellularOnly).last?.value == "Cellular only")
    }
}
