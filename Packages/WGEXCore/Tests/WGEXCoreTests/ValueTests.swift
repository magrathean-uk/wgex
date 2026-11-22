// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore

private struct ValueTests {
    @Test(arguments: [
        "192.0.2.1",
        "0.0.0.0/0",
        "192.0.2.7/32",
        "2001:db8::7/128",
        "::/0",
        "::1",
        "::ffff:192.0.2.1/128",
        "2001:0db8:0:0:0:0:0:1/64",
    ])
    func `IP forms round trip and preserve host bits`(text: String) throws {
        let value = try IPAddressRange(text)
        #expect(try IPAddressRange(value.stringRepresentation) == value)
        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(IPAddressRange.self, from: data) == value)
    }

    @Test(arguments: [
        "192.0.2.1/33",
        "::/129",
        "fe80::1%en0/64",
        "fe80::1%4",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4/-1",
        "::/",
        "::/64/1",
        "example.test/24",
        "::/+1",
    ])
    func `invalid IP forms throw`(text: String) {
        #expect(throws: ConfigurationError.invalidCIDR) { try IPAddressRange(text) }
    }

    @Test
    func `prefix containment compares bits in both families`() throws {
        #expect(try IPAddressRange("192.0.2.7/24").contains(IPAddressRange("192.0.2.255")))
        #expect(try !IPAddressRange("192.0.2.7/24").contains(IPAddressRange("192.0.3.1")))
        #expect(try IPAddressRange("2001:db8::/33").contains(IPAddressRange("2001:db8:7fff::1")))
        #expect(try !IPAddressRange("2001:db8::/33").contains(IPAddressRange("2001:db8:8000::1")))
        #expect(try !IPAddressRange("::/0").contains(IPAddressRange("192.0.2.1")))
        #expect(try !IPAddressRange("192.0.2.0/24").contains(IPAddressRange("192.0.0.0/16")))
    }

    @Test(arguments: [
        "192.0.2.1:51820",
        "[2001:db8::1]:443",
        "[::1]:65535",
        "peer.example.test:1",
        "localhost:53",
        "peer.example.test.:80",
    ])
    func `endpoints accept literals and DNS names without resolution`(text: String) throws {
        let endpoint = try Endpoint(text)
        #expect(try Endpoint(endpoint.stringRepresentation) == endpoint)
        #expect(try JSONDecoder().decode(Endpoint.self, from: JSONEncoder().encode(endpoint)) == endpoint)
    }

    @Test(arguments: [
        "host:0",
        "host:65536",
        "host:-1",
        "host:",
        "::1:80",
        "[::1]80",
        "[::1]:80:2",
        "[fe80::1%en0]:80",
        "bad name:80",
        "-host.test:80",
        ".test:80",
        "256.0.0.1:80",
        "[host]:80",
        "host: 80",
    ])
    func `invalid endpoints throw`(text: String) {
        #expect(throws: ConfigurationError.self) { try Endpoint(text) }
    }

    @Test(arguments: ["192.0.2.53", "2001:db8::53"])
    func `DNS servers accept literals`(text: String) throws {
        let server = try DNSServer(text)
        #expect(try JSONDecoder().decode(DNSServer.self, from: JSONEncoder().encode(server)) == server)
    }

    @Test(arguments: ["dns.example.test", "192.0.2.53/24", "fe80::1%en0"])
    func `DNS names and scopes are not resolver addresses`(text: String) {
        #expect(throws: ConfigurationError.invalidDNS) { try DNSServer(text) }
    }

    @Test
    func `Codable cannot bypass endpoint or key validation`() throws {
        #expect(throws: ConfigurationError.invalidPort) { try JSONDecoder().decode(
            Endpoint.self,
            from: Data(#"{"host":"peer.test","port":0}"#.utf8),
        ) }
        #expect(throws: KeyFormatError.invalidLength(1)) { try JSONDecoder().decode(PublicKey.self, from: Data(#""AA==""#.utf8)) }
    }

    @Test
    func `domain values satisfy Sendable at compile time`() {
        Self.sendable(IPAddressRange.self); Self.sendable(Endpoint.self); Self.sendable(DNSServer.self)
        Self.sendable(PublicKey.self); Self.sendable(SecretBytes.self); Self.sendable(PrivateKey.self); Self.sendable(PresharedKey.self)
        Self.sendable(Generation.self); Self.sendable(TransportID.self); Self.sendable(TunnelProfile.self)
    }

    private static func sendable(_: (some ~Copyable & Sendable).Type) {}
}
