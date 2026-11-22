// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

/// The editor keeps the DNS host routes of "Exclude private networks" in step with the DNS field,
/// however the field changes (DEC-020).
private struct EditorDNSHostRouteTests {
    private static let publicSet = CIDRBlock.subtracting([.allIPv4], excluding: CIDRBlock.privateIPv4).map(\.description)

    private var publicSet: [String] {
        Self.publicSet
    }

    /// The ipv6-dual-stack fixture: DNS `10.77.0.1, fd77:77::1`, one peer with `0.0.0.0/0, ::/0`.
    private func editor(dns: String? = nil) throws -> ProfileEditorModel {
        let parsed = try EditorFixtures.parsed()
        let model = try ProfileEditorModel(profile: parsed.profile, secrets: parsed.secrets)
        if let dns {
            model.draft.dns = dns
        }
        return model
    }

    private func texts(_ model: ProfileEditorModel, peer: Int = 0) -> [String] {
        model.draft.peers[peer].allowedIPs.texts
    }

    private func hostRoutes(_ model: ProfileEditorModel) -> Set<String> {
        Set(texts(model).filter { $0.hasSuffix("/32") || $0.hasSuffix("/128") })
    }

    @Test
    func `the editor passes the draft DNS and the saved profile keeps the resolver routed`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.excludePrivateNetworks(peerID: id)
        #expect(texts(model) == publicSet + ["::/0", "10.77.0.1/32", "fd77:77::1/128"])
        #expect(!model.diagnostics.contains { $0.diagnostic.code == .dnsOutsideAllowedIPs })
        let profile = try model.validatedProfile()
        let host = try IPAddressRange("10.77.0.1")
        #expect(profile.peers[0].allowedIPs.contains { $0.contains(host) })
        #expect(profile.interface.dns.map(\.stringRepresentation) == ["10.77.0.1", "fd77:77::1"])
    }

    @Test
    func `an imported excluded profile gains its missing host routes at the next DNS write`() throws {
        let model = try editor()
        model.draft.peers[0].allowedIPs = AllowedIPsModel(publicSet + ["::/0"])
        #expect(model.diagnostics.contains { $0.diagnostic.code == .dnsOutsideAllowedIPs })
        model.draft.dns = "10.77.0.1, fd77:77::1, 1.1.1.1"
        #expect(texts(model) == publicSet + ["::/0", "10.77.0.1/32", "fd77:77::1/128", "1.1.1.1/32"])
        #expect(!model.diagnostics.contains { $0.diagnostic.code == .dnsOutsideAllowedIPs })
    }

    @Test
    func `a profile without DNS excludes with no host route and adds one when DNS is set`() throws {
        let model = try editor(dns: "")
        let id = try #require(model.draft.peers.first?.id)
        model.excludePrivateNetworks(peerID: id)
        #expect(texts(model) == publicSet + ["::/0"])
        model.draft.dns = "10.77.0.1"
        #expect(texts(model).last == "10.77.0.1/32")
        model.draft.dns = ""
        #expect(texts(model) == publicSet + ["::/0"])
        #expect(model.draft.dns.isEmpty)
    }

    @Test
    func `editing the DNS field while excluded replaces the host routes`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.excludePrivateNetworks(peerID: id)
        model.draft.dns = "10.77.0.9, fd77:77::1"
        #expect(model.draft.dns == "10.77.0.9, fd77:77::1")
        #expect(hostRoutes(model) == ["10.77.0.9/32", "fd77:77::1/128"])
        #expect(texts(model).filter { $0 == "fd77:77::1/128" }.count == 1)
        let profile = try model.validatedProfile()
        #expect(profile.interface.dns.map(\.stringRepresentation) == ["10.77.0.9", "fd77:77::1"])
        #expect(!model.diagnostics.contains { $0.diagnostic.code == .dnsOutsideAllowedIPs })
    }

    @Test
    func `typing a resolver one character at a time leaves only the final host route`() throws {
        let model = try editor(dns: "")
        let id = try #require(model.draft.peers.first?.id)
        model.excludePrivateNetworks(peerID: id)
        let typed = "10.77.0.153"
        for count in 1 ... typed.count {
            model.draft.dns = String(typed.prefix(count))
        }
        #expect(hostRoutes(model) == ["10.77.0.153/32"])
        for count in (0 ..< typed.count).reversed() {
            model.draft.dns = String(typed.prefix(count))
        }
        #expect(texts(model) == publicSet + ["::/0"])
    }

    @Test
    func `split halves exclude and follow DNS writes exactly like 0_0_0_0 slash 0`() throws {
        let whole = try editor()
        let split = try editor()
        split.draft.peers[0].allowedIPs = AllowedIPsModel(["0.0.0.0/1", "128.0.0.0/1", "::/0"])
        for model in [whole, split] {
            let id = try #require(model.draft.peers.first?.id)
            model.excludePrivateNetworks(peerID: id)
            model.draft.dns = "10.77.0.9"
        }
        #expect(texts(split) == texts(whole))
        #expect(texts(split) == publicSet + ["::/0", "10.77.0.9/32"])
        let host = try IPAddressRange("10.77.0.9")
        #expect(try split.validatedProfile().peers[0].allowedIPs.contains { $0.contains(host) })
    }

    @Test
    func `a DNS write adds host routes only to the peers whose control is on`() throws {
        let model = try editor()
        let first = try #require(model.draft.peers.first?.id)
        model.addPeer()
        model.draft.peers[1].allowedIPs = AllowedIPsModel(["0.0.0.0/0", "::/0"])
        model.addPeer()
        model.draft.peers[2].allowedIPs = AllowedIPsModel(["::/0", "fd77:77::1/128"])
        model.excludePrivateNetworks(peerID: first)
        model.setPrivateNetworksExcluded(true, peerID: model.draft.peers[2].id)
        model.draft.dns = "10.77.0.9"
        #expect(hostRoutes(model) == ["10.77.0.9/32"])
        #expect(texts(model, peer: 1) == ["0.0.0.0/0", "::/0"])
        #expect(texts(model, peer: 2) == ["::/0", "fd77:77::1/128"])
    }

    @Test
    func `an off and on round trip with DNS writes and clearing leaves no stale host route`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.setPrivateNetworksExcluded(true, peerID: id)
        #expect(hostRoutes(model) == ["10.77.0.1/32", "fd77:77::1/128"])
        model.draft.dns = "10.77.0.9, fd77:77::2"
        #expect(hostRoutes(model) == ["10.77.0.9/32", "fd77:77::2/128"])
        model.draft.dns = ""
        #expect(texts(model) == publicSet + ["::/0"])
        model.setPrivateNetworksExcluded(false, peerID: id)
        #expect(texts(model) == ["0.0.0.0/0", "::/0"])
        for dns in ["10.77.0.5", "", "fd77:77::3"] {
            model.draft.dns = dns
            #expect(texts(model) == ["0.0.0.0/0", "::/0"])
        }
        model.setPrivateNetworksExcluded(true, peerID: id)
        #expect(texts(model) == publicSet + ["::/0", "fd77:77::3/128"])
        model.setPrivateNetworksExcluded(false, peerID: id)
        #expect(texts(model) == ["0.0.0.0/0", "::/0", "fd77:77::3/128"])
        model.setPrivateNetworksExcluded(true, peerID: id)
        #expect(texts(model) == publicSet + ["::/0", "fd77:77::3/128"])
        model.draft.dns = "10.77.0.5"
        #expect(texts(model) == publicSet + ["::/0", "10.77.0.5/32"])
        model.draft.dns = ""
        #expect(texts(model) == publicSet + ["::/0"])
        model.setPrivateNetworksExcluded(false, peerID: id)
        #expect(texts(model) == ["0.0.0.0/0", "::/0"])
    }

    @Test
    func `a DNS edit while off removes the departed host route so turning on again leaves only the new one`() throws {
        let model = try editor(dns: "fd77:77::1")
        model.draft.peers[0].allowedIPs = AllowedIPsModel(["0.0.0.0/0"])
        let id = try #require(model.draft.peers.first?.id)
        model.setPrivateNetworksExcluded(true, peerID: id)
        #expect(texts(model) == publicSet + ["fd77:77::1/128"])
        model.setPrivateNetworksExcluded(false, peerID: id)
        #expect(texts(model) == ["0.0.0.0/0", "fd77:77::1/128"])
        model.draft.dns = "fd77:77::2"
        #expect(texts(model) == ["0.0.0.0/0"])
        model.setPrivateNetworksExcluded(true, peerID: id)
        #expect(hostRoutes(model) == ["fd77:77::2/128"])
        #expect(texts(model) == publicSet + ["fd77:77::2/128"])
    }

    @Test
    func `a DNS edit while off keeps every route that is not a departed server's host route`() throws {
        let model = try editor()
        let typed = ["0.0.0.0/0", "::/0", "10.77.0.1/32", "192.168.1.10/32", "fd77:77::/64", "fd77:77::1/128", "fd77:77::2/127"]
        model.draft.peers[0].allowedIPs = AllowedIPsModel(typed)
        let before = model.draft.peers[0].allowedIPs.entries
        #expect(model.draft.peers[0].allowedIPs.privateNetworkExclusion(dnsServers: ["10.77.0.1", "fd77:77::1"]) == .off)
        model.draft.dns = "10.77.0.1, fd77:77::2"
        #expect(model.draft.peers[0].allowedIPs.entries == before.filter { $0.text != "fd77:77::1/128" })
        model.draft.dns = "8.8.8.8"
        #expect(model.draft.peers[0].allowedIPs.entries == before.filter { !["10.77.0.1/32", "fd77:77::1/128"].contains($0.text) })
    }

    @Test
    func `a DNS write marks the draft dirty and setting the same text does not`() throws {
        let model = try editor()
        let id = try #require(model.draft.peers.first?.id)
        model.excludePrivateNetworks(peerID: id)
        model.markSaved()
        #expect(!model.isDirty)
        let same = model.draft.dns
        model.draft.dns = same
        #expect(!model.isDirty)
        model.draft.dns = "10.77.0.9"
        #expect(model.isDirty)
    }
}
