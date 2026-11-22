// SPDX-License-Identifier: MIT

import Foundation

public enum ProbeSelfTest {
    /// All destinations and listeners are hard-coded loopback literals and ephemeral ports.
    public static func run() async throws -> ProbeRunRecord {
        let listener = try MarkerListener(addresses: ["127.0.0.1", "::1"], port: 0, dnsPort: 0)
        let configuration = ProbeConfiguration(targets: listener.targets)
        let nonce = UUID().uuidString.lowercased()
        let start = Date().timeIntervalSince1970
        async let received = listener.collect(seconds: 1.3)
        let sent = try await MarkerGenerator.run(configuration: configuration, nonce: nonce, rounds: 3)
        let observations = try await received
        for family in ["ipv4", "ipv6"] {
            for proto in [MarkerProtocol.dns, .http, .udp, .tcp] {
                guard observations.filter({ $0.nonce == nonce && $0.family == family && $0.proto == proto }).count == 3 else {
                    throw ProbeError.selftest
                }
            }
        }
        guard sent.allSatisfy({ $0.kind == .sent }), sent.count == 24 else { throw ProbeError.selftest }
        let record = try ProbeRunRecord(
            nonce: nonce,
            configuration: configuration,
            observations: (sent + observations).sorted { $0.timestamp < $1.timestamp },
            windows: [ObservationWindow(
                state: "unprotected",
                start: start,
                end: Date().timeIntervalSince1970,
                receiversComplete: true,
            )],
        )
        let encoded = try ProbeRunRecord.canonicalData(record)
        guard try JSONDecoder().decode(ProbeRunRecord.self, from: encoded) == record else { throw ProbeError.selftest }
        return record
    }
}
