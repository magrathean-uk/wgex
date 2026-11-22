// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Network
import Synchronization
import SystemConfiguration
import WGEXCore
import WGEXDaemonProtocol

/// Observes primary physical interfaces, resolver addresses and path changes.
public actor SystemUnderlayMonitor: UnderlayMonitoring {
    private let notifications = SystemConfigurationNotifications()
    private var tasks: [Task<Void, Never>] = []
    private var model = UnderlayMonitorModel()
    private var sink: AsyncStream<UnderlayEvent>.Continuation?
    private let ownedDNSKeys: @Sendable () -> Set<String>
    #if os(macOS)
        private var pathMonitor: NWPathMonitor?
    #endif
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init(ownedDNSKeys: @escaping @Sendable () -> Set<String> = { [] }) {
        self.ownedDNSKeys = ownedDNSKeys
    }

    deinit { for task in tasks {
        task.cancel()
    } }

    /// Starts observing changes and returns a bounded event stream.
    public func start() async throws -> AsyncStream<UnderlayEvent> {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard tasks.isEmpty else { throw DaemonFailure.hostAlreadyStarted }
            let changes = try await notifications.start(ignoring: ownedDNSKeys)
            let pair = AsyncStream<UnderlayEvent>.makeStream(bufferingPolicy: .bufferingNewest(32))
            sink = pair.continuation
            let paths = AsyncStream<Bool>.makeStream(bufferingPolicy: .bufferingNewest(16))
            let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
            monitor.pathUpdateHandler = { paths.continuation.yield($0.status == .satisfied) }
            monitor.start(queue: DispatchQueue(label: "WGEX.underlay.path")); pathMonitor = monitor
            tasks = [
                Task { [weak self] in for await _ in changes {
                    await self?.emit(satisfied: nil)
                } },
                Task { [weak self] in for await satisfied in paths.stream {
                    await self?.emit(satisfied: satisfied)
                } },
            ]
            return pair.stream
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Stops observation and releases owned notification resources.
    public func stop() async {
        for task in tasks {
            task.cancel()
        }; tasks = []
        #if os(macOS)
            pathMonitor?.cancel(); pathMonitor = nil
        #endif
        await notifications.stop(); sink?.finish(); sink = nil
    }

    #if os(macOS)
        private func emit(satisfied: Bool?) {
            do {
                let event = try Self.read(satisfied: satisfied)
                // Yield only changed primary/path snapshots; periodic liveness runs independently.
                if model.receive(event) {
                    sink?.yield(event)
                }
            } catch {
                // Retain observation after transient configd errors; the merged consumer
                // re-reads and queues a failed batch for the daemon tick.
                sink?.yield(UnderlayEvent(
                    snapshot: model.current?.snapshot ?? UnderlaySnapshot(v4: nil, v6: nil, resolvers: [], interfaceNames: []),
                    satisfied: false, readFailed: true,
                ))
            }
        }
    #endif

    /// Reads a current snapshot from the system.
    public static func read(satisfied: Bool? = nil) throws -> UnderlayEvent {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            return try UnderlayStoreReader.read { store in
                let v4 = UnderlayStoreReader.primary(store, family: "IPv4"), v6 = UnderlayStoreReader.primary(store, family: "IPv6")
                let names = [v4["PrimaryInterface"], v6["PrimaryInterface"]].compactMap(\.self)
                let indexes = Dictionary(names.map { ($0, if_nametoindex($0)) }, uniquingKeysWith: { first, _ in first })
                let services = Set([v4["PrimaryService"], v6["PrimaryService"]].compactMap(\.self))
                let resolvers = services.sorted().flatMap { service -> [String] in
                    let fields = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(service)/DNS" as CFString) as? [String: Any]
                    return fields?["ServerAddresses"] as? [String] ?? []
                }
                let subnets = UnderlayStoreReader.subnets(store, v4: v4, v6: v6)
                let snapshot = UnderlayMonitorModel.snapshot(
                    ipv4: v4,
                    ipv6: v6,
                    indexes: indexes,
                    resolvers: resolvers,
                    lanSubnets: subnets,
                )
                var mtu: UInt16 = 1500
                var list: UnsafeMutablePointer<ifaddrs>?
                guard getifaddrs(&list) == 0 else { throw DaemonFailure.hostSystem(errno) }
                defer { freeifaddrs(list) }
                var cursor = list
                while let item = cursor {
                    defer { cursor = item.pointee.ifa_next }
                    if names.contains(String(cString: item.pointee.ifa_name)),
                       item.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_LINK), let raw = item.pointee.ifa_data
                    {
                        mtu = min(mtu, UInt16(clamping: raw.assumingMemoryBound(to: if_data.self).pointee.ifi_mtu))
                    }
                }
                return UnderlayEvent(snapshot: snapshot, satisfied: satisfied ?? (snapshot.v4 != nil || snapshot.v6 != nil), mtu: mtu)
            }
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }
}

#if os(macOS)
    /// A synchronous cached store, protected because startup and notification reads may overlap.
    private enum UnderlayStoreReader {
        private static let store = Mutex<SCDynamicStore?>(nil)
        fileprivate static func primary(_ store: SCDynamicStore, family: String) -> [String: String] {
            let fields = SCDynamicStoreCopyValue(store, "State:/Network/Global/\(family)" as CFString) as? [String: Any] ?? [:]
            var primary: [String: String] = ["PrimaryInterface", "PrimaryService", "Router"].reduce(into: [:]) { result, key in
                if let value = fields[key] as? String {
                    result[key] = value
                }
            }
            if family == "IPv4", let service = primary["PrimaryService"] {
                let key = "State:/Network/Service/\(service)/IPv4"
                let value = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any]
                primary["Router"] = value?["Router"] as? String
            }
            return primary
        }

        fileprivate static func subnets(_ store: SCDynamicStore, v4: [String: String], v6: [String: String]) -> [IPAddressRange] {
            func entity(_ service: String?, _ family: String) -> [String: Any] {
                guard let service else { return [:] }
                return SCDynamicStoreCopyValue(store, "State:/Network/Service/\(service)/\(family)" as CFString) as? [String: Any] ??
                    [:]
            }
            let addresses4 = entity(v4["PrimaryService"], "IPv4"), addresses6 = entity(v6["PrimaryService"], "IPv6")
            return UnderlayMonitorModel.lanSubnets(
                addresses: addresses4["Addresses"] as? [String] ?? [], masks: addresses4["SubnetMasks"] as? [String] ?? [],
                addressesV6: addresses6["Addresses"] as? [String] ?? [], prefixes: addresses6["PrefixLength"] as? [Int] ?? [],
            )
        }

        fileprivate static func read<T: Sendable>(_ body: @Sendable (SCDynamicStore) throws -> T) throws -> T {
            try store.withLock { store in
                if store == nil {
                    store = SCDynamicStoreCreate(nil, "WGEX underlay" as CFString, nil, nil)
                }
                guard let store else { throw DaemonFailure.hostSystem(SCError()) }
                return try body(store)
            }
        }
    }
#endif
