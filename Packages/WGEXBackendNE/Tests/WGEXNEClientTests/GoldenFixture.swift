// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore

package enum GoldenFixture {
    package static let names = ["dual", "block", "allow", "flags-on", "flags-off", "flags-mixed", "carrier"]
    package static func profile(_ name: String = "dual") throws -> TunnelProfile {
        let id = try UUID(uuidString: "00000000-0000-0000-0000-000000000001").unwrap()
        let peer = try PublicKey(rawValue: Data(repeating: 2, count: 32))
        var profile = TunnelProfile(id: id, name: "Fixture", createdAt: Date(timeIntervalSince1970: 0))
        profile.interface = try InterfaceConfiguration(
            addresses: (name == "block" || name == "allow" ? ["10.8.0.2/32"] : ["10.8.0.2/24", "fd00::2/64"]).map(IPAddressRange.init),
            mtu: name == "carrier" ? 9000 : nil,
            dns: [DNSServer("10.8.0.1")], searchDomains: ["wgex.test"], publicKey: PublicKey(rawValue: Data(repeating: 1, count: 32)),
        )
        profile.peers = try [PeerConfiguration(
            publicKey: peer, allowedIPs: ["0.0.0.0/0", "::/0"].map(IPAddressRange.init), endpoint: Endpoint("192.0.2.1:51820"),
        )]
        profile.secrets = SecretReferences(privateKey: .keychain(persistentRef: Data([1, 2, 3])))
        profile.protection.ipv6Policy = name == "block" ? .blockOutside : .allowOutside
        if name == "flags-on" || name == "flags-off" {
            let flag = name == "flags-on"
            profile.protection.ios = IOSProtection(
                includeAllNetworks: flag, excludeLocalNetworks: flag, excludeCellularServices: flag,
                excludeAPNs: flag, excludeDeviceCommunication: flag,
            )
        }
        if name == "flags-mixed" {
            profile.protection.ios = IOSProtection(
                includeAllNetworks: true, excludeLocalNetworks: false, excludeCellularServices: true,
                excludeAPNs: false, excludeDeviceCommunication: true,
            )
        }
        profile.protection.dnsPolicy = name == "allow" ? .systemDefault : name == "block" ? .split(["internal.test"]) : .tunnelAll
        profile.onDemand = .wifiOnly(exceptSSIDs: ["Z", "A"])
        return profile
    }
}

private extension Optional {
    func unwrap() throws -> Wrapped {
        guard let self else { throw FixtureFailure.invalid }
        return self
    }
}

private enum FixtureFailure: Error { case invalid }
