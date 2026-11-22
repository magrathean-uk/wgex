// SPDX-License-Identifier: MIT

/// Inner transport of a tunnel (02 §8.1). Only `.udp` exists until phase 6
/// adds the carrier transports.
public enum TransportSpec: Codable, Sendable, Hashable {
    /// Plain WireGuard over UDP.
    case udp
}
