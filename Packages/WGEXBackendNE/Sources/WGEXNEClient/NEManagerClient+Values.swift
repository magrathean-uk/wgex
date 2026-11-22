// SPDX-License-Identifier: Apache-2.0 AND MIT

// Adapted from firezone swift/apple FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift at
// 229ac31b37b5fbde2961e7f87df8181abd7fd46f, Apache-2.0
// Copyright Firezone, Inc. Licensed under Apache-2.0; see Vendor/firezone/NOTICE and LICENSE.
import CryptoKit
import Foundation
import WGEXCore

/// Pure values the client derives from what the system reports and from a profile.
extension NEManagerClient {
    public static func status(_ status: VPNStatus, generation: Generation = .initial) -> TunnelStatus {
        var result = TunnelStatus.idle
        result.phase = switch status {
        case .invalid: .failed(.backendUnavailable, blockedByPolicy: false, needsSecrets: false)
        case .disconnected: .idle
        case .connecting: .preparing(generation)
        case .connected: .active(generation)
        case .reasserting: .reasserting(generation, reason: .pathChanged)
        case .disconnecting: .stopping(generation, reason: .userRequested)
        }
        // Device protection proofs are required before claiming blocked or protected.
        result.protection = status == .disconnected ? .unprotected : .unknown
        return result
    }

    /// Digest of the profile fields the provider reads when it starts or reloads. Name, on-demand rules, Mac options,
    /// retained import text and timestamps are left out: none of them reaches a running tunnel. Secrets appear only as
    /// Keychain references, and unordered maps are sorted so the digest is stable across launches.
    package static func profileRevision(_ profile: TunnelProfile) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        func sorted(_ map: [some Encodable & Hashable: SecretRef]) -> [[Data]] {
            map.compactMap { key, value -> [Data]? in
                guard let encodedKey = try? encoder.encode(key), let encodedValue = try? encoder.encode(value) else { return nil }
                return [encodedKey, encodedValue]
            }
            .sorted { $0[0].lexicographicallyPrecedes($1[0]) }
        }
        let applied = AppliedProfile(
            schemaVersion: profile.schemaVersion, interface: profile.interface, peers: profile.peers,
            privateKey: profile.secrets.privateKey, presharedKeys: sorted(profile.secrets.presharedKeys),
            carrierCredentials: sorted(profile.secrets.carrierCredentials), transport: profile.transport,
            protection: profile.protection,
        )
        let data = (try? encoder.encode(applied)) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private struct AppliedProfile: Encodable {
    let schemaVersion: Int
    let interface: InterfaceConfiguration
    let peers: [PeerConfiguration]
    let privateKey: SecretRef
    let presharedKeys: [[Data]]
    let carrierCredentials: [[Data]]
    let transport: TransportPolicy
    let protection: ProtectionPolicy
}
