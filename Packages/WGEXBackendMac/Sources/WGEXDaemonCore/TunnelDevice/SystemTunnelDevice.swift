// SPDX-License-Identifier: MIT
import CWGEXSysShim
import Darwin
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXEngineInterface

/// Configures only the utun this process still holds: the journalled name, index and descriptor (M1-18).
public struct SystemTunnelDevice: TunnelDeviceConfiguring {
    private let identities: any InterfaceIdentityReading
    private let journal: any DaemonJournalling
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init(identities: any InterfaceIdentityReading, journal: any DaemonJournalling) {
        self.identities = identities; self.journal = journal
    }

    /// Applies addresses and MTU only after checking journal ownership.
    public func configure(_ identity: TunnelIdentity, addresses: [IPAddressRange], mtu: UInt16, generation: Generation) async throws {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            try await checkIdentity(identity)
            guard journal.snapshot().resources.contains(where: { $0.generation == generation && $0.identity == identity }),
                  mtu >= (addresses.contains(where: \.isIPv6) ? 1280 : 576)
            else { throw DaemonFailure.portNotOwned }
            for address in addresses {
                try await apply(address, identity: identity, remove: false)
            }
            try await checkIdentity(identity)
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
            defer { close(fd) }
            let result = identity.name.withCString { wgex_interface_mtu(fd, $0, Int32(mtu)) }
            guard result == 0 else { throw DaemonFailure.hostSystem(result) }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Confirms the utun after this daemon's own address and MTU change: the same name and index, this process's
    /// descriptor still open and reporting the name, and every journalled address present (M1-18). The kernel's
    /// ifi_lastchange may have moved; it is not compared.
    public func identity(afterConfiguring identity: TunnelIdentity) async throws -> TunnelIdentity {
        let addresses = journal.snapshot().resources.first { $0.identity == identity }?.addresses ?? []
        try await checkIdentity(identity, addresses: addresses)
        return identity
    }

    /// Confirms the device as above, then the engine that holds the descriptor: present and reporting the name.
    public func identity(afterConfiguring identity: TunnelIdentity, engine: any EngineControlling?) async throws -> TunnelIdentity {
        let confirmed = try await self.identity(afterConfiguring: identity)
        guard let engine, try await engine.statistics().interfaceName == identity.name else {
            #if WGEX_LAB_BUILD
                DaemonDiagnostics.ownership(.engineInterfaceMismatch)
            #endif
            throw DaemonFailure.portNotOwned
        }
        return confirmed
    }

    /// Removes journalled addresses only while this process still holds the utun.
    public func removeAddresses(_ identity: TunnelIdentity, generation: Generation) async throws {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard try await identities.admits(identity, fence: .tunnel(addresses: [])),
                  let resource = journal.snapshot().resources.first(where: { $0.generation == generation && $0.identity == identity })
            else { return }
            for address in resource.addresses {
                try await apply(address, identity: identity, remove: true)
            }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Lab builds name a refusal and the failed fence check (M1-18); the failure itself is unchanged.
    private func checkIdentity(_ identity: TunnelIdentity, addresses: [IPAddressRange] = []) async throws {
        guard let refusal = try await identities.breach(of: identity, fence: .tunnel(addresses: addresses)) else { return }
        #if WGEX_LAB_BUILD
            DaemonDiagnostics.ownership(.deviceInterfaceDrift)
            DaemonDiagnostics.interface(identity, current: refusal.1, breach: refusal.0)
        #else
            _ = refusal
        #endif
        throw DaemonFailure.portNotOwned
    }

    #if os(macOS)
        private func apply(_ address: IPAddressRange, identity: TunnelIdentity, remove: Bool) async throws {
            try await checkIdentity(identity)
            let fd = socket(address.isIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)
            guard fd >= 0 else { throw DaemonFailure.hostSystem(errno) }
            defer { close(fd) }
            let result = address.bytes.withUnsafeBufferPointer { bytes in
                identity.name.withCString { wgex_interface_address(
                    fd,
                    $0,
                    bytes.baseAddress,
                    Int32(bytes.count),
                    Int32(address.prefixLength),
                    remove ? 1 : 0,
                ) }
            }
            guard result == 0 || (!remove && result == EEXIST) || (remove && result == EADDRNOTAVAIL) else {
                throw DaemonFailure.hostSystem(result)
            }
        }
    #endif
}
