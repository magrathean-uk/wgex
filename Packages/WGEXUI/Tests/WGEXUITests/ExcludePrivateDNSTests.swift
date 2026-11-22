// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXUI

/// DEC-020: one predicate over a peer's IPv4 AllowedIPs decides the "Exclude private networks"
/// control; turning it on appends each DNS server's host route (the daemon routes AllowedIPs only),
/// and a DNS change while it is on reconciles those routes.
private struct ExcludePrivateDNSTests {
    private static let everything = ["0.0.0.0/0", "::/0"]
    /// The public IPv4 set the exclusion keeps, computed independently of the model.
    private static let publicSet = CIDRBlock.subtracting([.allIPv4], excluding: CIDRBlock.privateIPv4).map(\.description)

    private var publicSet: [String] {
        Self.publicSet
    }

    private func state(_ texts: [String], dns: [String] = []) -> AllowedIPsModel.PrivateNetworkExclusion {
        AllowedIPsModel(texts).privateNetworkExclusion(dnsServers: dns)
    }

    private func on(_ texts: [String] = everything, dns: [String]) -> AllowedIPsModel {
        var model = AllowedIPsModel(texts)
        model.setPrivateNetworksExcluded(true, dnsServers: dns)
        return model
    }

    private func routed(_ model: AllowedIPsModel, _ address: String) throws -> Bool {
        let host = try CIDRBlock(parsing: address)
        return model.blocks.contains { $0.contains(host) }
    }

    /// Every IPv4 address except `hole`, as prefixes.
    private func allIPv4(except hole: String) throws -> [String] {
        try CIDRBlock.subtracting([.allIPv4], excluding: [CIDRBlock(parsing: hole)]).map(\.description)
    }

    // MARK: The predicate

    @Test
    func `any cover of all IPv4 reads as off and behaves like 0_0_0_0 slash 0`() {
        let covers: [[String]] = [
            ["0.0.0.0/0"], ["0.0.0.0/1", "128.0.0.0/1"], ["0.0.0.0/1", "128.0.0.0/1", "::/0"],
            ["128.0.0.0/1", "::/0", "64.0.0.0/2", "0.0.0.0/2"], ["0.0.0.0/0", "10.0.0.0/8", "8.8.8.8/32", "fd00::/8"],
        ]
        for texts in covers {
            let ipv6 = texts.filter { $0.contains(":") }
            #expect(state(texts) == .off)
            #expect(state(texts, dns: ["10.77.0.1"]) == .off)
            var model = AllowedIPsModel(texts)
            model.reconcileDNSHostRoutes(from: ["10.77.0.1"], to: ["10.77.0.9"])
            #expect(model.texts == texts)
            model.setPrivateNetworksExcluded(true, dnsServers: ["10.77.0.1"])
            #expect(model.texts == publicSet + ipv6 + ["10.77.0.1/32"])
            model.setPrivateNetworksExcluded(false, dnsServers: ["10.77.0.1"])
            #expect(model.texts == ["0.0.0.0/0"] + ipv6)
        }
        let split = AllowedIPsModel(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"])
        #expect(split.routesAllTraffic)
        #expect(split.summary == "All traffic")
    }

    @Test
    func `the public set reads as on with or without extra private entries`() throws {
        let first = try CIDRBlock(parsing: publicSet[0])
        let halves = try #require(first.halves())
        let rewritten = [halves.1.description, halves.0.description] + publicSet.dropFirst()
        for base in [publicSet, rewritten] {
            for extra in [[], ["192.168.50.0/24"], ["10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"], ["10.77.0.1/32"]] {
                #expect(state(base + extra) == .on)
                #expect(state(base + extra + ["::/0"], dns: ["10.77.0.1"]) == .on)
            }
        }
        #expect(state(publicSet + ["192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16", "10.0.0.0/8"]) == .off)
    }

    @Test
    func `anything else has no control and is never changed by it`() throws {
        let none: [[String]] = try [
            [], ["::/0"], ["fd00::/8", "::/0"], ["fd77:77::1/128", "::/0"], ["8.8.8.0/24"], ["8.8.8.0/24", "::/0"],
            ["10.0.0.0/8", "::/0"], ["0.0.0.0/1"], Array(publicSet.dropFirst()), ["10.77.0.1/32", "::/0"],
            ["not an address", "::/0"], allIPv4(except: "8.8.8.8/32"),
        ]
        for texts in none {
            #expect(state(texts) == .unavailable)
            #expect(state(texts, dns: ["10.77.0.1", "fd77:77::1"]) == .unavailable)
            var model = AllowedIPsModel(texts)
            model.setPrivateNetworksExcluded(true, dnsServers: ["10.77.0.1", "fd77:77::1"])
            #expect(model.texts == texts)
            model.setPrivateNetworksExcluded(false, dnsServers: ["10.77.0.1", "fd77:77::1"])
            #expect(model.texts == texts)
            model.reconcileDNSHostRoutes(from: ["10.77.0.1", "fd77:77::1"], to: ["10.77.0.9", "fd77:77::2"])
            model.reconcileDNSHostRoutes(from: ["10.77.0.9", "fd77:77::2"], to: [])
            #expect(model.texts == texts)
        }
    }

    @Test
    func `IPv6 entries never affect the control`() {
        for ipv6 in [[], ["::/0"], ["fd00::/8"], ["::/1", "8000::/1"], ["fd77:77::1/128"], ["::/0", "2001:db8::53/128"]] {
            #expect(state(["0.0.0.0/0"] + ipv6, dns: ["fd77:77::1"]) == .off)
            #expect(state(publicSet + ipv6, dns: ["fd77:77::1"]) == .on)
            #expect(state(["8.8.8.0/24"] + ipv6, dns: ["fd77:77::1"]) == .unavailable)
        }
    }

    @Test
    func `only the exact host routes of the current DNS servers are ignored`() throws {
        let resolverHole = try allIPv4(except: "10.77.0.1/32") + ["10.77.0.1/32"]
        #expect(state(resolverHole) == .off)
        #expect(state(resolverHole, dns: ["10.77.0.1"]) == .on)
        #expect(state(resolverHole, dns: ["10.77.0.2"]) == .off)
        let pairHole = try allIPv4(except: "10.77.0.0/31") + ["10.77.0.0/31"]
        #expect(state(pairHole, dns: ["10.77.0.1"]) == .off)
        let publicHole = try CIDRBlock.subtracting(CIDRBlock.subtracting([.allIPv4], excluding: CIDRBlock.privateIPv4), excluding: [
            CIDRBlock(parsing: "8.8.8.8/32"),
        ]).map(\.description) + ["8.8.8.8/32"]
        #expect(state(publicHole) == .on)
        #expect(state(publicHole, dns: ["8.8.8.8"]) == .unavailable)
    }

    @Test
    func `a hand-typed public subset has no control`() {
        var model = AllowedIPsModel(["8.8.8.0/24"])
        #expect(model.privateNetworkExclusion(dnsServers: ["8.8.8.8"]) == .unavailable)
        model.excludePrivateNetworks(dnsServers: ["8.8.8.8"])
        #expect(model.texts == ["8.8.8.0/24"])
        model.reconcileDNSHostRoutes(from: [], to: ["8.8.8.8"])
        model.reconcileDNSHostRoutes(from: ["8.8.8.8"], to: ["1.1.1.1"])
        #expect(model.texts == ["8.8.8.0/24"])
        #expect(model.summaryText(dnsServers: ["1.1.1.1"]) == "1 range")
    }

    // MARK: Turning the control on and off

    @Test
    func `turning on keeps every IPv6 entry and appends each host route once`() throws {
        var model = AllowedIPsModel(["0.0.0.0/0", "fd00::/8", "not an address", "10.77.0.1/32", "::/0", "fd77:77::1/128"])
        let keptTexts = ["fd00::/8", "not an address", "::/0", "fd77:77::1/128"]
        let kept = model.entries.filter { keptTexts.contains($0.text) }
        let dns = ["10.77.0.1", "fd77:77::1", "8.8.8.8", "10.77.0.1", " fe80::1 ", "resolver.example"]
        model.setPrivateNetworksExcluded(true, dnsServers: dns)
        #expect(model.texts == publicSet + keptTexts + ["10.77.0.1/32", "8.8.8.8/32", "fe80::1/128"])
        #expect(Array(model.entries[publicSet.count ..< publicSet.count + kept.count]) == kept)
        #expect(try routed(model, "10.77.0.1"))
        #expect(try !routed(model, "10.77.0.2"))
        #expect(try !routed(model, "192.168.1.1"))
        #expect(model.privateNetworkExclusion(dnsServers: ["10.77.0.1", "fd77:77::1", "8.8.8.8", "fe80::1"]) == .on)
    }

    @Test
    func `turning off restores 0_0_0_0 slash 0 and keeps IPv6 entries as they are`() {
        var model = on(["0.0.0.0/0", "::/0", "fd00::/8"], dns: ["10.77.0.1", "fd77:77::1"])
        model.add("192.168.50.0/24")
        model.add("not an address")
        model.setPrivateNetworksExcluded(false, dnsServers: ["10.77.0.1", "fd77:77::1"])
        #expect(model.texts == ["0.0.0.0/0", "::/0", "fd00::/8", "fd77:77::1/128", "not an address"])
        #expect(model.privateNetworkExclusion(dnsServers: ["10.77.0.1", "fd77:77::1"]) == .off)
    }

    @Test
    func `the control acts only on a change of state`() {
        var model = on(dns: ["10.77.0.1"])
        model.add("192.168.50.0/24")
        let before = model
        model.excludePrivateNetworks(dnsServers: ["10.77.0.1", "10.77.0.9"])
        #expect(model == before)
        var split = AllowedIPsModel(["0.0.0.0/1", "128.0.0.0/1", "::/0"])
        split.setPrivateNetworksExcluded(false, dnsServers: ["10.77.0.1"])
        #expect(split.texts == ["0.0.0.0/1", "128.0.0.0/1", "::/0"])
    }

    @Test
    func `a profile without DNS gets no host route`() {
        let plain = on(dns: [])
        #expect(plain.texts == publicSet + ["::/0"])
        var legacy = AllowedIPsModel(Self.everything)
        legacy.excludePrivateNetworks()
        #expect(legacy == plain)
        #expect(on(dns: ["resolver.example", "", "10.0.0.0/8", "999.1.1.1"]).texts == plain.texts)
        #expect(plain.summary == "All traffic except private networks")
    }

    // MARK: DNS changes while on

    @Test
    func `a DNS change while on removes departed host routes and adds every missing one`() throws {
        var model = on(dns: ["10.77.0.1"])
        let survivors = model.entries.dropLast().map(\.id)
        model.reconcileDNSHostRoutes(from: ["10.77.0.1"], to: ["10.77.0.9", "fd77:77::1"])
        #expect(model.texts == publicSet + ["::/0", "10.77.0.9/32", "fd77:77::1/128"])
        #expect(Array(model.entries.map(\.id).prefix(survivors.count)) == survivors)
        #expect(try routed(model, "10.77.0.9"))
        #expect(try !routed(model, "10.77.0.1"))
        model.reconcileDNSHostRoutes(from: ["10.77.0.9", "fd77:77::1"], to: ["8.8.8.8", "fd77:77::1"])
        #expect(model.texts == publicSet + ["::/0", "fd77:77::1/128", "8.8.8.8/32"])
        model.reconcileDNSHostRoutes(from: ["8.8.8.8", "fd77:77::1"], to: [])
        #expect(model.texts == publicSet + ["::/0"])
    }

    @Test
    func `a typed host route equal to a departing server is removed and every other typed route survives`() {
        var model = AllowedIPsModel(["0.0.0.0/0", "::/0", "fd77:77::1/128", "2001:db8::/32", "fd77:77::2/128", "not an address"])
        model.setPrivateNetworksExcluded(true, dnsServers: ["fd77:77::1"])
        #expect(model.texts.filter { $0 == "fd77:77::1/128" }.count == 1)
        for typed in ["192.168.50.0/24", "10.1.2.3/32", "8.8.4.4/32", "fd77:77:0::1/127"] {
            model.add(typed)
        }
        let survivors = model.entries.filter { $0.text != "fd77:77::1/128" }
        model.reconcileDNSHostRoutes(from: ["fd77:77::1"], to: [])
        #expect(model.entries == survivors)
        #expect(model.privateNetworkExclusion(dnsServers: []) == .on)
    }

    @Test
    func `an IPv6-only peer has no control and a dual-stack peer keeps the resolver slash 128 in step`() {
        for texts in [["::/0"], ["::/0", "fd77:77::1/128"], ["10.0.0.0/8", "::/0"]] {
            var model = AllowedIPsModel(texts)
            #expect(model.privateNetworkExclusion(dnsServers: ["fd77:77::1"]) == .unavailable)
            model.setPrivateNetworksExcluded(true, dnsServers: ["fd77:77::1"])
            model.reconcileDNSHostRoutes(from: ["fd77:77::1"], to: ["fd77:77::2"])
            model.reconcileDNSHostRoutes(from: ["fd77:77::2"], to: [])
            #expect(model.texts == texts)
        }
        var model = on(dns: ["fd77:77::1"])
        #expect(model.texts == publicSet + ["::/0", "fd77:77::1/128"])
        model.reconcileDNSHostRoutes(from: ["fd77:77::1"], to: ["fd77:77::2"])
        #expect(model.texts == publicSet + ["::/0", "fd77:77::2/128"])
        model.reconcileDNSHostRoutes(from: ["fd77:77::2"], to: [])
        #expect(model.texts == publicSet + ["::/0"])
    }

    @Test
    func `an imported excluded profile gains the missing host route at its next DNS change`() {
        var model = AllowedIPsModel(publicSet + ["::/0"])
        #expect(model.privateNetworkExclusion(dnsServers: ["fd77:77::1"]) == .on)
        model.reconcileDNSHostRoutes(from: ["fd77:77::1"], to: ["fd77:77::1", "1.1.1.1"])
        #expect(model.texts == publicSet + ["::/0", "fd77:77::1/128", "1.1.1.1/32"])
        var same = AllowedIPsModel(publicSet + ["::/0"])
        same.reconcileDNSHostRoutes(from: ["fd77:77::1"], to: ["fd77:77::1", "resolver.example"])
        #expect(same.texts == publicSet + ["::/0", "fd77:77::1/128"])
    }

    @Test
    func `the public set plus an extra private entry stays on and DNS changes still reconcile`() {
        var model = on(dns: ["10.77.0.1"])
        model.add("192.168.50.0/24")
        #expect(model.privateNetworkExclusion(dnsServers: ["10.77.0.1"]) == .on)
        #expect(model.summaryText(dnsServers: ["10.77.0.1"]) == "All traffic except private networks")
        model.reconcileDNSHostRoutes(from: ["10.77.0.1"], to: ["10.77.0.9"])
        #expect(model.texts == publicSet + ["::/0", "192.168.50.0/24", "10.77.0.9/32"])
        model.reconcileDNSHostRoutes(from: ["10.77.0.9"], to: [])
        #expect(model.texts == publicSet + ["::/0", "192.168.50.0/24"])
    }

    // MARK: Summary

    @Test
    func `the summary reads the same predicate`() throws {
        #expect(on(dns: ["10.77.0.1"]).summaryText(dnsServers: ["10.77.0.1"]) == "All traffic except private networks")
        #expect(on(["0.0.0.0/0"], dns: ["10.77.0.1"]).summaryText(dnsServers: ["10.77.0.1"]) == "All IPv4 traffic except private networks")
        #expect(on(["0.0.0.0/1", "128.0.0.0/1"], dns: []).summary == "All IPv4 traffic except private networks")
        #expect(on(["0.0.0.0/0", "fd00::/8"], dns: []).summary == "All IPv4 traffic except private networks")
        #expect(AllowedIPsModel(["0.0.0.0/1", "128.0.0.0/1", "::/0"]).summary == "All traffic")
        #expect(AllowedIPsModel(["0.0.0.0/1", "128.0.0.0/1"]).summary == "2 ranges")
        #expect(AllowedIPsModel(["10.77.0.1/32", "::/0"]).summaryText(dnsServers: ["10.77.0.1"]) == "2 ranges")
        let resolverHole = try allIPv4(except: "10.77.0.1/32") + ["10.77.0.1/32", "::/0"]
        #expect(AllowedIPsModel(resolverHole).summaryText(dnsServers: []) == "All traffic")
        #expect(AllowedIPsModel(resolverHole).summaryText(dnsServers: ["10.77.0.1"]) == "All traffic except private networks")
    }

    @Test
    func `all traffic drops the DNS host routes`() {
        var model = on(dns: ["10.77.0.1", "fd77:77::1"])
        model.setAllTraffic()
        #expect(model.texts == Self.everything)
        model.reconcileDNSHostRoutes(from: ["10.77.0.1"], to: ["10.77.0.2"])
        #expect(model.texts == Self.everything)
    }
}
