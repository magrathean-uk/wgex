// SPDX-License-Identifier: MIT

import Foundation
import LeakProbe
import Testing

private struct LeakProbeTests {
    @Test(arguments: [MarkerFormat.marker, .leak], [false, true])
    func `marker wire format round trips`(format: MarkerFormat, ipv6: Bool) throws {
        let dns = try MarkerWire.dns(nonce: "test-123", format: format, ipv6: ipv6)
        #expect(MarkerWire.dnsNonce(dns) == "test-123")
        let http = try MarkerWire.http(nonce: "test-123", format: format, host: ipv6 ? "[::1]" : "127.0.0.1")
        #expect(MarkerWire.nonce(http)?.0 == "test-123")
        #expect(MarkerWire.nonce(http)?.1 == .http)
        #expect(try MarkerWire.nonce(MarkerWire.udp(nonce: "test-123"))?.1 == .udp)
    }

    @Test
    func `latency bounds and system resolver names are explicit`() throws {
        let config = ProbeConfiguration(targets: [ProbeTarget(address: "127.0.0.1", scope: .outsideTunnel)], tcpTimeoutMilliseconds: 1500)
        #expect(throws: Never.self) { try config.validate() }
        #expect(try MarkerWire.systemResolverName(nonce: "fixture") == "fixture-system.leak.wgex.test")
        #expect(throws: (any Error).self) { try MarkerWire.systemResolverName(nonce: "bad.name") }
        let invalid = ProbeConfiguration(targets: config.targets, tcpTimeoutMilliseconds: 0)
        #expect(throws: (any Error).self) { try invalid.validate() }
    }

    @Test
    func `untrusted marker packets are rejected`() throws {
        for nonce in ["", "a.b", "A", "abc\r\nHost: other", String(repeating: "a", count: 64)] {
            #expect(!MarkerWire.validNonce(nonce))
            #expect(throws: (any Error).self) { try MarkerWire.dns(nonce: nonce, format: .marker, ipv6: false) }
        }
        let valid = try MarkerWire.dns(nonce: "test", format: .marker, ipv6: false)
        for size in 0 ..< valid.count {
            #expect(MarkerWire.dnsNonce(valid.prefix(size)) == nil)
        }
        #expect(MarkerWire.dnsNonce(valid + Data([0])) == nil)
        #expect(MarkerWire.nonce(Data("GET /marker/bad?nonce HTTP/1.1\r\n\r\n".utf8)) == nil)
        #expect(throws: (any Error).self) { try MarkerWire.http(nonce: "test", format: .marker, host: "host\r\nInjected: true") }
        #expect(throws: (any Error).self) { try ProbeTarget(address: "example.test", scope: .inTunnel).validate() }
    }

    @Test
    func `record encoding is stable hashed and lossless`() throws {
        let config = ProbeConfiguration(targets: [ProbeTarget(address: "127.0.0.1", scope: .outsideTunnel)])
        let observation = MarkerObservation(
            timestamp: 1,
            nonce: "test",
            kind: .received,
            scope: .outsideTunnel,
            family: "ipv4",
            proto: .udp,
            address: "127.0.0.1",
            port: 8088,
        )
        let record = try ProbeRunRecord(nonce: "test", configuration: config, observations: [observation])
        let bytes = try ProbeRunRecord.canonicalData(record)
        #expect(try bytes == ProbeRunRecord.canonicalData(record))
        #expect(try record.configurationSHA256 == ProbeRunRecord.hash(ProbeRunRecord.canonicalData(config)))
        #expect(try JSONDecoder().decode(ProbeRunRecord.self, from: bytes) == record)
        #expect(record.configurationSHA256.count == 64)
        #expect(ProbeRunRecord.hash(Data("abc".utf8)) == ("ba7816bf8f01cfea414140de5dae2223b0" + "0361a396177a9cb410ff61f20015ad"))
    }

    @Test
    func `loopback selftest receives every protocol on both families`() async throws {
        let record = try await ProbeSelfTest.run()
        #expect(record.configuration.targets.map(\.address) == ["127.0.0.1", "::1"])
        #expect(record.observations.filter { $0.kind == .received }.count == 24)
        #expect(record.observations.filter { $0.kind == .sent }.count == 24)
        #expect(record.windows.first?.state == "unprotected")
        #expect(record.windows.first?.receiversComplete == true)
    }
}
