// SPDX-License-Identifier: MIT

import Darwin
import Foundation

public enum MarkerGenerator {
    /// Only numeric destinations; no system resolver, proxy, redirects or URLSession.
    /// Each round starts on a monotonic 500 ms schedule; HTTP connection attempts are bounded.
    public static func run(configuration: ProbeConfiguration, nonce: String, rounds: Int) async throws -> [MarkerObservation] {
        try configuration.validate()
        guard MarkerWire.validNonce(nonce), rounds > 0, rounds <= 172_800 else { throw ProbeError.configuration("nonce or rounds") }
        let clock = ContinuousClock(), start = ContinuousClock.now
        var observations: [MarkerObservation] = []
        try await withThrowingTaskGroup(of: [MarkerObservation].self) { group in
            for index in 0 ..< rounds {
                try Task.checkCancellation()
                let next = start.advanced(by: .milliseconds(index * configuration.intervalMilliseconds))
                try await clock.sleep(until: next)
                for target in configuration.targets {
                    group.addTask {
                        await Task.detached {
                            emit(
                                target: target,
                                nonce: nonce,
                                format: configuration.format,
                                timeout: Int32(configuration.tcpTimeoutMilliseconds ?? 100),
                            )
                        }.value
                    }
                }
            }
            for try await result in group {
                observations += result
            }
        }
        return observations.sorted { $0.timestamp < $1.timestamp }
    }

    private static func emit(target: ProbeTarget, nonce: String, format: MarkerFormat, timeout: Int32) -> [MarkerObservation] {
        var observations: [MarkerObservation] = []
        for proto in [MarkerProtocol.dns, .http, .udp, .tcp] {
            let port = proto == .dns ? target.dnsPort : ((proto == .http || proto == .tcp) ? target.httpPort : target.udpPort)
            let host = proto == .dns ? target.resolver ?? target.address : target.address
            var kind = ObservationKind.sent, detail: String?
            do {
                let literalHost = target.family == "ipv6" ? "[\(target.address)]" : target.address
                let authority = target.httpPort == 80 ? literalHost : "\(literalHost):\(target.httpPort)"
                let data: Data = switch proto {
                case .dns: try MarkerWire.dns(nonce: nonce, format: format, ipv6: target.family == "ipv6")
                case .http: try MarkerWire.http(nonce: nonce, format: format, host: target.httpHost ?? authority)
                default: try MarkerWire.udp(nonce: nonce)
                }
                let address = try ProbeAddress(host: host, port: port, type: (proto == .http || proto == .tcp) ? SOCK_STREAM : SOCK_DGRAM)
                let socket = try ProbeSocket(address: address, type: (proto == .http || proto == .tcp) ? SOCK_STREAM : SOCK_DGRAM)
                try socket.send(data, to: address, tcp: proto == .http || proto == .tcp, timeoutMilliseconds: timeout)
            } catch {
                kind = .failure; detail = String(describing: error)
            }
            observations.append(MarkerObservation(
                nonce: nonce,
                kind: kind,
                scope: target.scope,
                family: host.contains(":") ? "ipv6" : "ipv4",
                proto: proto,
                address: host,
                port: port,
                allowedLAN: target.allowedLAN,
                detail: detail,
            ))
        }
        return observations
    }
}
