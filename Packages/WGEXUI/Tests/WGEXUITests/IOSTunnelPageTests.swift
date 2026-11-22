// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

/// The iPhone and iPad tunnel page (SPEC 10): the Mac page's groups, live rows only while up, no invented values.
private struct IOSTunnelPageTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let generation = Generation(rawValue: 7)

    private func home() throws -> TunnelProfile {
        var profile = TunnelProfile(name: "Home")
        profile.interface.addresses = try [IPAddressRange("10.8.0.2/24"), IPAddressRange("fd00:8::2/64")]
        profile.interface.dns = try [DNSServer("10.8.0.1")]
        profile.peers = try [.init(
            publicKey: profile.interface.publicKey,
            allowedIPs: [.allIPv4],
            endpoint: Endpoint("vpn.example.net:51820"),
            persistentKeepalive: 25,
        )]
        profile.onDemand = .iosInterfaces(.wifiOnly(.anySSID))
        return profile
    }

    private func active() -> TunnelStatus {
        var status = TunnelStatus.idle
        status.phase = .active(generation)
        status.protection = .protected
        return status
    }

    private func sample(_ profile: TunnelProfile) -> TunnelStatistics {
        TunnelStatistics(generation: 7, sampledAt: now, interfaceName: "utun4", listenPort: nil, peers: [
            PeerStatistics(
                publicKey: profile.peers[0].publicKey, endpoint: nil, lastHandshake: now.addingTimeInterval(-18),
                rxBytes: 1_500_000, txBytes: 84000, persistentKeepalive: 25,
            ),
        ])
    }

    private func page(
        _ profile: TunnelProfile, status: TunnelStatus, active: UUID?, statistics: TunnelStatistics? = nil,
        protection: ProtectionPolicy = ProtectionPolicy(ipv6Policy: .tunnel), device: IOSTunnelPagePresentation.Device = .iPhone,
    ) -> IOSTunnelPagePresentation {
        IOSTunnelPagePresentation(
            profile: profile, status: status, activeProfileID: active, userInitiated: true,
            statistics: statistics, protection: protection, device: device, now: now,
        )
    }

    private func row(_ page: IOSTunnelPagePresentation, _ id: String) -> TunnelPageRow? {
        page.groups.flatMap(\.rows).first { $0.id == id }
    }

    @Test func `the active tunnel shows the Mac groups in order with live totals`() throws {
        let profile = try home()
        let page = page(profile, status: active(), active: profile.id, statistics: sample(profile), device: .iPad)
        #expect(page.status.word == MacStrings.active)
        #expect(page.status.detail == nil)
        #expect(page.groups.map(\.id) == ["traffic", "addresses", "server.0", "protection", "advanced"])
        #expect(row(page, "download")?.value == UIFormat.bytes(1_500_000))
        #expect(row(page, "upload")?.value == UIFormat.bytes(84000))
        #expect(row(page, "lastHandshake")?.value == "18 seconds ago")
        #expect(row(page, "interface")?.value == "utun4")
        #expect(row(page, "publicKey")?.label == PlatformStrings.thisIPadsPublicKey)
        #expect(row(page, "publicKey")?.copyValue == profile.interface.publicKey.base64)
        #expect(row(page, "mtu")?.value == MacStrings.automatic)
        #expect(row(page, "routes")?.value == MacStrings.allTraffic)
    }

    private func protectionNote(_ status: TunnelStatus, up: Bool = true) throws -> String? {
        let profile = try home()
        return page(profile, status: status, active: up ? profile.id : UUID()).groups.first { $0.id == "protection" }?.note
    }

    @Test func `exclusion notes show under the protection group only while up`() throws {
        var status = active()
        #expect(try protectionNote(status) == nil)
        status.forceAllIgnoredExclusions = ["10.0.0.0/8"]
        #expect(try protectionNote(status) == UserStrings.exclusionsForceAllTraffic)
        #expect(try protectionNote(status, up: false) == nil)
        status.forceAllIgnoredExclusions = []
        status.unsupportedExclusionPorts = ["tcp/443"]
        #expect(try protectionNote(status) == UserStrings.exclusionPortsUnsupported(["tcp/443"]))
        status.unsupportedExclusionPorts = []
        status.unresolvedExclusions = ["example.com"]
        #expect(try protectionNote(status) == UserStrings.exclusionUnresolved(["example.com"]))
    }

    @Test func `exclusion notes combine one per line`() throws {
        var status = active()
        status.forceAllIgnoredExclusions = ["10.0.0.0/8"]
        status.unsupportedExclusionPorts = ["tcp/443"]
        status.unresolvedExclusions = ["example.com"]
        #expect(try protectionNote(status)?.split(separator: "\n").count == 3)
    }

    @Test func `an inactive tunnel has no live rows and never shows another tunnel's counters`() throws {
        let profile = try home()
        let page = page(profile, status: active(), active: UUID(), statistics: sample(profile))
        #expect(page.status.state == .inactive)
        #expect(page.status.word == MacStrings.inactive)
        #expect(page.status.detail == nil)
        #expect(!page.groups.map(\.id).contains("traffic"))
        #expect(row(page, "interface") == nil)
        #expect(row(page, "peer.0.address") == nil)
        #expect(row(page, "peer.0.name")?.value == "vpn.example.net")
        #expect(row(page, "publicKey")?.label == PlatformStrings.thisIPhonesPublicKey)
    }

    @Test func `an active tunnel without a sample says Unavailable rather than zero`() throws {
        let profile = try home()
        let page = page(profile, status: active(), active: profile.id)
        #expect(row(page, "download")?.value == MacStrings.unavailable)
        #expect(row(page, "lastHandshake")?.value == MacStrings.unavailable)
        #expect(row(page, "interface")?.value == MacStrings.unavailable)
    }

    @Test func `protection rows report app-wide state and the tunnel's on-demand rule`() throws {
        let profile = try home()
        var policy = ProtectionPolicy(ipv6Policy: .tunnel)
        policy.ios.includeAllNetworks = true
        policy.ios.excludeLocalNetworks = false
        let page = page(profile, status: .idle, active: nil, protection: policy)
        let protection = try #require(page.groups.first { $0.id == "protection" })
        #expect(protection.rows.map(\.id) == ["forceAllTraffic", "localNetwork", "exclusions", "onDemand"])
        #expect(protection.rows.map(\.link) == [.protectionPage, .protectionPage, nil, .onDemand])
        #expect(row(page, "exclusions")?.value == MacStrings.exclusionsNone)
        #expect(row(page, "forceAllTraffic")?.value == MacStrings.killSwitchOn)
        #expect(row(page, "localNetwork")?.value == MacStrings.localNetworkNotAllowed)
        #expect(row(page, "onDemand")?.value == IOSOnDemandForm(policy: profile.onDemand).activationSummary)
    }

    @Test func `the exclusions row counts the tunnel's exclusions and leads to the list`() throws {
        var profile = try home()
        profile.exclusions = try TunnelExclusions(entries: ["192.168.50.0/24", "nas.example.com"])
        let page = page(profile, status: .idle, active: nil)
        #expect(page.exclusions == ["192.168.50.0/24", "nas.example.com"])
        #expect(row(page, "exclusions")?.value == MacStrings.exclusionCount(2))
        #expect(row(page, "exclusions")?.link == .exclusions)
        #expect(row(page, "exclusions")?.copyValue == "192.168.50.0/24, nas.example.com")
    }

    @Test func `the list word shows only for the active tunnel`() throws {
        let profile = try home()
        #expect(IOSTunnelPagePresentation.listWord(
            profileID: profile.id,
            status: active(),
            activeProfileID: profile.id,
            userInitiated: true,
        )
            == MacStrings.active)
        #expect(IOSTunnelPagePresentation.listWord(profileID: profile.id, status: active(), activeProfileID: UUID(), userInitiated: true)
            == nil)
        #expect(IOSTunnelPagePresentation.listWord(profileID: profile.id, status: .idle, activeProfileID: profile.id, userInitiated: true)
            == nil)
    }

    @Test func `connecting says it is waiting for the server`() throws {
        let profile = try home()
        var status = TunnelStatus.idle
        status.phase = .preparing(generation)
        status.protection = .blocked
        let page = page(profile, status: status, active: profile.id)
        #expect(page.status.word == MacStrings.menuActivating)
        #expect(page.status.detail == MacStrings.menuWaiting)
        #expect(!page.groups.map(\.id).contains("traffic"))
    }
}
