// SPDX-License-Identifier: MIT
import Foundation
import SystemConfiguration
import WGEXCore
import WGEXDaemonProtocol

/// All Core Foundation state stays on this actor. Nothing is created until a guarded method is called.
public actor SystemDNSSession: DNSSession {
    #if os(macOS)
        private var store: SCDynamicStore?

        private func session() throws -> SCDynamicStore {
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            if let store {
                return store
            }
            guard let created = SCDynamicStoreCreate(nil, "WGEX DNS" as CFString, nil, nil) else {
                throw DaemonFailure.hostSystem(SCError())
            }
            store = created; return created
        }
    #endif
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {}

    /// Reads a current snapshot from the system.
    public func read(key: String) throws -> SyntheticDNSValue? {
        #if os(macOS)
            let store = try session()
            guard let raw = SCDynamicStoreCopyValue(store, key as CFString) else { return nil }
            guard let fields = raw as? [String: Any], fields.count == 4,
                  let servers = fields["ServerAddresses"] as? [String], let search = fields["SearchDomains"] as? [String],
                  let matches = fields["SupplementalMatchDomains"] as? [String], let order = fields["SearchOrder"] as? Int
            else { throw DaemonFailure.portNotOwned }
            return try SyntheticDNSValue(
                configuration: DNSConfiguration(servers: servers, searchDomains: search, matchDomains: matches), searchOrder: order,
            )
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Removes the owned synthetic DNS key.
    public func remove(key: String) throws {
        #if os(macOS)
            let store = try session()
            guard SCDynamicStoreCopyValue(store, key as CFString) != nil else { return }
            guard SCDynamicStoreRemoveValue(store, key as CFString) else { throw DaemonFailure.hostSystem(SCError()) }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Publishes the synthetic DNS value for this session lifetime.
    public func addTemporary(key: String, value: SyntheticDNSValue) throws {
        #if os(macOS)
            let store = try session()
            let fields: [String: Any] = [
                "ServerAddresses": value.configuration.servers, "SearchDomains": value.configuration.searchDomains,
                "SupplementalMatchDomains": value.configuration.matchDomains, "SearchOrder": value.searchOrder,
            ]
            guard SCDynamicStoreAddTemporaryValue(store, key as CFString, fields as CFDictionary) else {
                throw DaemonFailure.hostSystem(SCError())
            }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Reads the resolver ordering through the fixed scutil executable.
    public func resolverListing() async throws -> String {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            let result = try await PFProcessExecutor(executable: URL(fileURLWithPath: "/usr/sbin/scutil"))
                .run(arguments: ["--dns"], input: Data(), deadline: 3)
            guard result.status == 0 else { throw DaemonFailure.hostSystem(result.status) }
            return result.stdout
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }
}
