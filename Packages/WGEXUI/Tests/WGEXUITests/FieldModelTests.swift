// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXUI

private struct FieldModelTests {
    @Test(arguments: [
        ("10.0.0.0/8", "10.0.0.0/8"), ("10.0.0.2", "10.0.0.2/32"), (" 192.168.1.0/24 ", "192.168.1.0/24"),
        ("fd00::/8", "fd00::/8"), ("::/0", "::/0"), ("2001:db8::1", "2001:db8::1/128"), ("0.0.0.0/0", "0.0.0.0/0"),
    ])
    func `prefixes parse and print canonically`(_ text: String, _ canonical: String) throws {
        #expect(try CIDRBlock(parsing: text).description == canonical)
    }

    @Test(arguments: [
        ("", CIDRParseError.empty), ("10.0.0", .invalidAddress), ("10.0.0.0/33", .invalidPrefix(maximum: 32)),
        ("fd00::/129", .invalidPrefix(maximum: 128)), ("10.0.0.0/", .invalidPrefix(maximum: 32)), ("fe80::1%en0/64", .invalidAddress),
        ("vpn.example.com", .invalidAddress), ("10.0.0.0/8/8", .invalidAddress), ("010.0.0.1", .invalidAddress), (
            "10.0.0.0/+8",
            .invalidPrefix(maximum: 32),
        ),
    ])
    func `bad prefixes are rejected with a message`(_ text: String, _ error: CIDRParseError) {
        #expect(throws: error) { try CIDRBlock(parsing: text) }
        #expect(!error.message.isEmpty)
    }

    @Test
    func `containment, host bits and halves`() throws {
        let ten = try CIDRBlock(parsing: "10.0.0.0/8")
        #expect(try ten.contains(CIDRBlock(parsing: "10.1.2.3")))
        #expect(try !ten.contains(CIDRBlock(parsing: "11.0.0.1")))
        #expect(!ten.contains(CIDRBlock.allIPv6))
        #expect(try CIDRBlock(parsing: "10.0.0.2/24").hasHostBits)
        let halves = try #require(ten.halves())
        #expect(halves.0.description == "10.0.0.0/9")
        #expect(halves.1.description == "10.128.0.0/9")
        #expect(try CIDRBlock(parsing: "10.0.0.1").halves() == nil)
    }

    @Test
    func `excluding private networks covers every public address and nothing private`() throws {
        let remaining = CIDRBlock.subtracting([.allIPv4], excluding: CIDRBlock.privateIPv4)
        let size = remaining.reduce(UInt64(0)) { $0 + (UInt64(1) << UInt64(32 - $1.prefixLength)) }
        let excluded: UInt64 = (1 << 24) + (1 << 20) + (1 << 16) + (1 << 16)
        #expect(size == (UInt64(1) << 32) - excluded)
        for address in ["8.8.8.8", "172.32.0.1", "172.15.255.255", "192.169.0.1", "100.64.0.1", "1.1.1.1"] {
            let host = try CIDRBlock(parsing: address)
            let routed = remaining.contains { $0.contains(host) }
            #expect(routed, "\(address) should be routed")
        }
        for address in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.10.10"] {
            let host = try CIDRBlock(parsing: address)
            let routed = remaining.contains { $0.contains(host) }
            #expect(!routed, "\(address) should be excluded")
        }
        let disjoint = zip(remaining, remaining.dropFirst()).allSatisfy { !$0.overlaps($1) }
        #expect(disjoint)
    }

    @Test
    func `the AllowedIPs helpers`() {
        var model = AllowedIPsModel(text: "10.0.0.0/8, fd00::/8")
        #expect(model.isValid)
        #expect(model.summary == "2 ranges")
        model.setAllTraffic()
        #expect(model.texts == ["0.0.0.0/0", "::/0"])
        #expect(model.routesAllTraffic)
        #expect(model.summary == "All traffic")
        #expect(!model.excludesPrivateNetworks)
        model.excludePrivateNetworks()
        #expect(model.excludesPrivateNetworks)
        #expect(!model.routesAllTraffic)
        #expect(model.texts.last == "::/0")
        #expect(model.summary == "All traffic except private networks")
        #expect(model.isValid)
    }

    @Test
    func `the AllowedIPs editor keeps what it cannot parse`() {
        var model = AllowedIPsModel(["0.0.0.0/0", "not an address"])
        #expect(!model.isValid)
        #expect(model.validations == [.valid, .invalid("Invalid address")])
        model.excludePrivateNetworks()
        #expect(model.texts.last == "not an address")
        #expect(model.summary == "All IPv4 traffic except private networks")
        model.add("192.168.0.0/16")
        #expect(model.excludesPrivateNetworks)
        let id = model.entries[0].id
        model.remove(id: id)
        let stillThere = model.entries.contains { $0.id == id }
        #expect(!stillThere)
        #expect(!model.excludesPrivateNetworks)
        #expect(AllowedIPsModel().isValid == false)
        #expect(model.text.contains(", "))
    }

    @Test(arguments: [
        ("vpn.example.com:51820", "vpn.example.com", UInt16(51820)), ("203.0.113.7:443", "203.0.113.7", 443),
        ("[2001:db8::1]:51820", "2001:db8::1", 51820), ("host-1.example.:1", "host-1.example.", 1),
    ])
    func `endpoints parse`(_ text: String, _ host: String, _ port: UInt16) throws {
        let endpoint = try EndpointText.parse(text).get()
        #expect(endpoint.host == host)
        #expect(endpoint.port == port)
        #expect(EndpointField.validate(text) == .valid)
    }

    @Test(arguments: [
        ("", EndpointParseError.empty), ("vpn.example.com", .missingPort), ("vpn.example.com:0", .invalidPort),
        ("vpn.example.com:65536", .invalidPort), ("vpn.example.com:http", .invalidPort), ("2001:db8::1:51820", .invalidHost),
        ("[2001:db8::1]51820", .missingPort), ("[nonsense]:1", .invalidHost), ("-bad.example:1", .invalidHost),
        ("999.1.1.1:1", .invalidHost), ("under_score.example:1", .invalidHost),
    ])
    func `bad endpoints are rejected`(_ text: String, _ error: EndpointParseError) {
        #expect(throws: error) { try EndpointText.parse(text).get() }
        #expect(EndpointField.validate(text) == (error == .empty ? .empty : .invalid(error.message)))
    }

    @Test
    func `endpoints format with brackets for IPv6`() throws {
        let ipv6 = try #require(try? Endpoint(validatingHost: "2001:db8::1", port: 51820))
        let hostname = try #require(try? Endpoint(validatingHost: "vpn.example.com", port: 51820))
        #expect(EndpointText.format(ipv6) == "[2001:db8::1]:51820")
        #expect(EndpointText.format(hostname) == "vpn.example.com:51820")
    }

    @Test
    func `reveal once`() {
        var state = SecretRevealState()
        #expect(state.canReveal)
        let first = state.reveal()
        #expect(first)
        #expect(state.phase == .revealed)
        state.hide()
        #expect(state.phase == .spent)
        let second = state.reveal()
        #expect(!second)
        #expect(state.phase == .spent)
        #expect(SecretRevealState.mask.count == 12)
    }

    @Test
    func `copy policy per platform`() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(SecretCopyPolicy.iOS.options(now: now) == SecretPasteboardOptions(localOnly: true, expiresAt: now.addingTimeInterval(60)))
        #expect(SecretCopyPolicy.mac.options(now: now) == SecretPasteboardOptions(localOnly: true, expiresAt: nil))
        #expect(SecretCopyPolicy.tvOS.options(now: now) == nil)
        #expect(SecretCopyPolicy.mac.lifetimeSeconds == 60)
        #if os(macOS)
            #expect(SecretCopyPolicy.current == .mac)
        #endif
    }
}
