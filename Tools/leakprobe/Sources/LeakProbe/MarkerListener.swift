// SPDX-License-Identifier: MIT

import Darwin
import Foundation

/// An ordinary UDP/TCP receiver. Explicit addresses prevent accidental wildcard capture.
/// This is a marker service, never a packet capture or BPF reader.
public struct MarkerListener: Sendable {
    private struct Binding: Sendable {
        let socket: ProbeSocket
        let target: ProbeTarget
        let proto: MarkerProtocol
        let port: UInt16
    }

    private let bindings: [Binding]
    public let targets: [ProbeTarget]

    public init(addresses: [String], scope: MarkerScope = .outsideTunnel, port: UInt16 = 8088, dnsPort: UInt16 = 5354) throws {
        guard !addresses.isEmpty else { throw ProbeError.configuration("listener addresses") }
        var bindings: [Binding] = [], targets: [ProbeTarget] = []
        for host in addresses {
            guard ProbeTarget.isLiteral(host),
                  !["0.0.0.0", "::"].contains(host) else { throw ProbeError.configuration("specific listener address") }
            var sockets: [(ProbeSocket, MarkerProtocol, UInt16)] = []
            for proto in [MarkerProtocol.http, .udp, .dns] {
                let type = proto == .http ? SOCK_STREAM : SOCK_DGRAM
                let address = try ProbeAddress(host: host, port: proto == .dns ? dnsPort : port, type: type)
                let socket = try ProbeSocket(address: address, type: type)
                let boundPort = try socket.bind(address, tcp: proto == .http)
                sockets.append((socket, proto, boundPort))
            }
            let target = ProbeTarget(address: host, scope: scope, dnsPort: sockets[2].2, httpPort: sockets[0].2, udpPort: sockets[1].2)
            targets.append(target)
            bindings += sockets.map { Binding(socket: $0.0, target: target, proto: $0.1, port: $0.2) }
        }
        self.bindings = bindings; self.targets = targets
    }

    public func collect(seconds: TimeInterval) async throws -> [MarkerObservation] {
        guard seconds > 0, seconds <= 86400 else { throw ProbeError.configuration("listener duration") }
        return await Task.detached { receive(seconds: seconds) }.value
    }

    private func receive(seconds: TimeInterval) -> [MarkerObservation] {
        let end = ProcessInfo.processInfo.systemUptime + seconds
        var observations: [MarkerObservation] = []
        var descriptors = bindings.map { pollfd(fd: $0.socket.descriptor, events: Int16(POLLIN), revents: 0) }
        while ProcessInfo.processInfo.systemUptime < end {
            guard poll(&descriptors, nfds_t(descriptors.count), 20) > 0 else { continue }
            for index in bindings.indices where descriptors[index].revents & Int16(POLLIN) != 0 {
                let binding = bindings[index]
                let data = binding.proto == .http ? receiveTCP(binding.socket) : receiveUDP(binding.socket)
                guard let data, let (nonce, parsedProtocol) = MarkerWire.nonce(data) else { continue }
                let observedProtocol: MarkerProtocol = binding.proto == .http && parsedProtocol == .udp ? .tcp : parsedProtocol
                observations.append(MarkerObservation(
                    nonce: nonce,
                    kind: .received,
                    scope: binding.target.scope,
                    family: binding.target.family,
                    proto: observedProtocol,
                    address: binding.target.address,
                    port: binding.port,
                ))
            }
        }
        return observations
    }

    private func receiveUDP(_ socket: ProbeSocket) -> Data? {
        var bytes = [UInt8](repeating: 0, count: 4096)
        var source = sockaddr_storage(), length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &source) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(socket.descriptor, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { return nil }
        let data = Data(bytes.prefix(count))
        if MarkerWire.dnsNonce(data) != nil {
            var reply = Array(data); reply[2] = 0x81; reply[3] = 0x80
            withUnsafePointer(to: &source) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                    _ = reply.withUnsafeBytes { sendto(socket.descriptor, $0.baseAddress, $0.count, 0, address, length) }
                }
            }
        }
        return data
    }

    private func receiveTCP(_ listener: ProbeSocket) -> Data? {
        let descriptor = accept(listener.descriptor, nil, nil)
        guard descriptor >= 0 else { return nil }
        let client = ProbeSocket(accepted: descriptor)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 1024)
        let end = ProcessInfo.processInfo.systemUptime + 0.1
        while data.count < 4096, ProcessInfo.processInfo.systemUptime < end {
            guard client.wait(Int16(POLLIN), milliseconds: 10) else { continue }
            let count = recv(descriptor, &bytes, min(bytes.count, 4096 - data.count), 0)
            guard count > 0 else { break }
            data.append(contentsOf: bytes.prefix(count))
            if data.range(of: Data("\r\n\r\n".utf8)) != nil {
                break
            }
        }
        let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".utf8)
        _ = response.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
        return data
    }
}
