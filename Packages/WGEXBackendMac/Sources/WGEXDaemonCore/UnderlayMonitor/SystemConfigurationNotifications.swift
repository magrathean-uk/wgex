// SPDX-License-Identifier: MIT
import Dispatch
import Foundation
import SystemConfiguration
import WGEXDaemonProtocol

/// A callback owns only a Sendable stream continuation. CF retains the box while callbacks are registered.
private final class ConfigurationSink: Sendable {
    private let sink: AsyncStream<Void>.Continuation
    private let ignoring: @Sendable () -> Set<String>
    fileprivate init(_ sink: AsyncStream<Void>.Continuation, ignoring: @escaping @Sendable () -> Set<String>) {
        self.sink = sink; self.ignoring = ignoring
    }

    fileprivate func emit(_ keys: [String]) {
        let owned = ignoring()
        if keys.contains(where: { SystemConfigurationNotifications.isRelevant($0, ignoring: owned) }) {
            sink.yield(())
        }
    }
}

/// Owns dynamic-store notifications for underlay or console changes.
public actor SystemConfigurationNotifications {
    #if os(macOS)
        private var store: SCDynamicStore?
    #endif
    private var sink: AsyncStream<Void>.Continuation?
    /// Creates the system adapter; runtime resources are acquired by its methods.
    public init() {}

    /// Starts observing changes and returns a bounded event stream.
    public func start(consoleOnly: Bool = false, ignoring: @escaping @Sendable () -> Set<String> = { [] }) throws -> AsyncStream<Void> {
        #if os(macOS)
            #if WGEX_LAB_BUILD
                guard LabGuard.isLabHost() else { throw DaemonFailure.hostLabRequired }
            #endif
            guard store == nil else { throw DaemonFailure.hostAlreadyStarted }
            let pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(32))
            let box = ConfigurationSink(pair.continuation, ignoring: ignoring)
            var context = SCDynamicStoreContext(
                version: 0, info: Unmanaged.passUnretained(box).toOpaque(),
                retain: { pointer in
                    UnsafeRawPointer(Unmanaged<ConfigurationSink>.fromOpaque(pointer).retain().toOpaque())
                },
                release: { pointer in
                    Unmanaged<ConfigurationSink>.fromOpaque(pointer).release()
                }, copyDescription: nil,
            )
            guard let created = SCDynamicStoreCreate(nil, "WGEX notifications" as CFString, { _, keys, raw in
                guard let raw else { return }
                Unmanaged<ConfigurationSink>.fromOpaque(raw).takeUnretainedValue().emit(keys as? [String] ?? [])
            }, &context) else { throw DaemonFailure.hostSystem(SCError()) }
            let keys = consoleOnly ? ["State:/Users/ConsoleUser"] : ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"]
            let patterns = consoleOnly ? [] : ["State:/Network/Service/.*/DNS", "State:/Network/Interface/.*/IPv[46]"]
            guard SCDynamicStoreSetNotificationKeys(created, keys as CFArray, patterns as CFArray),
                  SCDynamicStoreSetDispatchQueue(created, DispatchQueue(label: "WGEX.configd.notifications"))
            else { throw DaemonFailure.hostSystem(SCError()) }
            store = created; sink = pair.continuation
            pair.continuation.onTermination = { [weak self] _ in Task { await self?.stop() } }
            pair.continuation.yield(())
            return pair.stream
        #else
            throw DaemonFailure.hostUnsupportedPlatform
        #endif
    }

    /// Compares exact owned DNS keys; physical primary service UUIDs remain observable.
    package nonisolated static func isRelevant(_ key: String, ignoring owned: Set<String>) -> Bool {
        !owned.contains(key) && !key.contains("/WGEX-") && !key.contains("/wgex") && !key.contains("/utun")
            && !key.contains("/awdl") && !key.contains("/llw")
    }

    /// Stops observation and releases owned notification resources.
    public func stop() {
        #if os(macOS)
            if let store {
                SCDynamicStoreSetDispatchQueue(store, nil)
            }
            store = nil
        #endif
        sink?.finish(); sink = nil
    }
}
