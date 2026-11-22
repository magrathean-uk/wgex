// SPDX-License-Identifier: Apache-2.0 AND MIT

// Adapted from firezone swift/apple FirezoneKit/Sources/FirezoneKit/Managers/VPNConfigurationManager.swift at
// 229ac31b37b5fbde2961e7f87df8181abd7fd46f, Apache-2.0
// Copyright Firezone, Inc. Licensed under Apache-2.0; see Vendor/firezone/NOTICE and LICENSE.
import Foundation
import NetworkExtension
import WGEXCore

/// A missing or oversize reply is a configuration error. Pure value logic, so host tests cover it without NE objects.
package func providerReplyOutcome(_ reply: Data?) -> Result<Data, any Error> {
    guard let reply, reply.count <= ProviderCodec.maximumBytes else { return .failure(NEVPNError(.configurationInvalid)) }
    return .success(reply)
}

/// Real preferences adapter. Never instantiate or invoke from host tests.
/// All non-Sendable NE objects stay on MainActor; only value copies leave it.
@MainActor
public final class NetworkExtensionManagerSystem: VPNManagerSystem {
    private var managers: [UUID: NETunnelProviderManager] = [:]
    private var records: [UUID: VPNManagerRecord] = [:]
    private var continuations: [UUID: AsyncStream<VPNStatusEvent>.Continuation] = [:]
    private var sequence: UInt64 = 0
    private var observation: any NSObjectProtocol?

    public init() {}

    @MainActor public func loadAll() async throws -> [VPNManagerRecord] {
        // Drop every previously mutated instance, including after a failed save.
        managers = [:]; records = [:]
        let loaded = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in loaded {
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let data = proto.providerConfiguration?["wgex.configuration"] as? Data,
                  let configuration = try? JSONDecoder().decode(ProtocolConfiguration.self, from: data),
                  proto.providerBundleIdentifier == configuration.providerBundleIdentifier else { continue }
            let id = configuration.profileID
            managers[id] = manager
            records[id] = VPNManagerRecord(
                id: id, configuration: configuration, name: manager.localizedDescription ?? "WGEX",
                isEnabled: manager.isEnabled, isOnDemandEnabled: manager.isOnDemandEnabled,
                status: Self.map(manager.connection.status),
                profileRevision: proto.providerConfiguration?[Self.revisionKey] as? String,
            )
        }
        return Array(records.values)
    }

    @MainActor public func save(_ record: VPNManagerRecord) async throws {
        let manager = managers[record.id] ?? NETunnelProviderManager()
        managers[record.id] = manager
        let proto = try Self.makeProtocol(record.configuration)
        proto.providerConfiguration?[Self.revisionKey] = record.profileRevision
        manager.protocolConfiguration = proto
        manager.localizedDescription = record.name
        manager.isEnabled = record.isEnabled
        manager.onDemandRules = Self.makeRules(record.configuration.onDemandRules)
        manager.isOnDemandEnabled = record.isOnDemandEnabled
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        records[record.id] = record
    }

    /// The profile revision lives beside the configuration; it is a digest, never key material.
    private static let revisionKey = "wgex.profileRevision"

    @MainActor public func remove(_ id: UUID) async throws {
        guard let manager = managers[id] else { throw NEVPNError(.configurationInvalid) }
        try await manager.removeFromPreferences()
        managers[id] = nil; records[id] = nil
    }

    public func start(_ id: UUID, transport: UUID?) throws {
        guard let record = records[id], let session = managers[id]?.connection as? NETunnelProviderSession else {
            throw NEVPNError(.configurationInvalid)
        }
        try session.startTunnel(options: Self.startOptions(record, transport: transport))
    }

    /// The waiter is this call's own observer and single-resume gate, never the shared status stream. Observer, start
    /// request and first status read run in one MainActor step, so no status change can fall between them.
    @MainActor public func startConfirmed(_ id: UUID, revision: String?) async throws {
        guard let manager = managers[id], let record = records[id] else { throw NEVPNError(.configurationInvalid) }
        // The manager must still hold the edit this restart applies; the start reads exactly that configuration.
        let saved = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[Self.revisionKey] as? String
        guard saved == revision else { throw TunnelError.cancelled }
        guard let session = manager.connection as? NETunnelProviderSession else { throw NEVPNError(.configurationInvalid) }
        let watch = StartWatch(connection: manager.connection)
        defer { watch.end() }
        let gate = watch.gate
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                gate.install(continuation)
                guard !Task.isCancelled else {
                    gate.finish(.failure(CancellationError()))
                    return
                }
                watch.arm()
                do {
                    try session.startTunnel(options: Self.startOptions(record, transport: nil))
                } catch {
                    gate.finish(.failure(error))
                    return
                }
                watch.inspect()
            }
        } onCancel: { gate.finish(.failure(CancellationError())) }
    }

    private static func startOptions(_ record: VPNManagerRecord, transport: UUID?) -> [String: NSObject] {
        var options: [String: NSObject] = ["profileID": record.configuration.profileID.uuidString as NSString]
        if let transport {
            options["transportID"] = transport.uuidString as NSString
        }
        return options
    }

    @MainActor public func stop(_ id: UUID) async throws {
        guard let manager = managers[id] else { throw NEVPNError(.configurationInvalid) }
        manager.connection.stopVPNTunnel()
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while manager.connection.status != .disconnected, manager.connection.status != .invalid {
            guard ContinuousClock.now < deadline else { throw TunnelError.timedOut }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    public func statusEvents() -> AsyncStream<VPNStatusEvent> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<VPNStatusEvent>.makeStream(bufferingPolicy: .bufferingNewest(64))
        continuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { @MainActor in self?.continuations[id] = nil } }
        if observation == nil {
            observation = NotificationCenter.default
                .addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
                    Task { @MainActor in self?.emitStatuses() }
                }
        }
        emitStatuses()
        return stream
    }

    @MainActor public func sendProviderMessage(_ id: UUID, data: Data) async throws -> Data {
        guard data.count <= ProviderCodec.maximumBytes,
              let session = managers[id]?.connection as? NETunnelProviderSession else { throw NEVPNError(.configurationInvalid) }
        // The SDK has no async variant of sendProviderMessage. The gate resumes the continuation once on every path
        // (reply, nil or oversize reply, throw, cancellation); a repeated or late callback is dropped.
        let gate = SingleResume<Data>()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                gate.install(continuation)
                // A send cancelled before it reaches the session is never made, so a caller that gave up on it can follow
                // it with another message knowing this one cannot arrive later. The check and the send run together here.
                guard !Task.isCancelled else {
                    gate.finish(.failure(CancellationError()))
                    return
                }
                do {
                    try session.sendProviderMessage(data, responseHandler: Self.replyHandler(gate))
                } catch { gate.finish(.failure(error)) }
            }
        } onCancel: { gate.finish(.failure(CancellationError())) }
    }

    /// Built outside MainActor isolation and `@Sendable`, so the SDK may call it on any queue without an isolation check.
    private nonisolated static func replyHandler(_ gate: SingleResume<Data>) -> @Sendable (Data?) -> Void {
        { @Sendable reply in gate.finish(providerReplyOutcome(reply)) }
    }

    public static func makeProtocol(_ value: ProtocolConfiguration) throws -> NETunnelProviderProtocol {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = value.providerBundleIdentifier
        proto.serverAddress = value.serverAddress
        proto.passwordReference = value.passwordReference
        proto.providerConfiguration = try ["profileID": value.profileID.uuidString, "wgex.configuration": JSONEncoder().encode(value)]
        #if os(iOS)
            if let flags = value.ios {
                proto.includeAllNetworks = flags.includeAllNetworks
                proto.excludeLocalNetworks = flags.excludeLocalNetworks
                proto.excludeCellularServices = flags.excludeCellularServices
                proto.excludeAPNs = flags.excludeAPNs
                proto.excludeDeviceCommunication = flags.excludeDeviceCommunication
            }
        #endif
        #if os(tvOS)
            proto.enforceRoutes = true
        #endif
        return proto
    }

    private static func makeRules(_ rules: [ProtocolConfiguration.Rule]) -> [NEOnDemandRule] {
        rules.map { value in
            let rule: NEOnDemandRule = value.action == .connect ? NEOnDemandRuleConnect() : NEOnDemandRuleDisconnect()
            switch value.interface {
            case .any: rule.interfaceTypeMatch = .any
            case .wifi: rule.interfaceTypeMatch = .wiFi
            case .cellular:
                #if os(iOS)
                    rule.interfaceTypeMatch = .cellular
                #else
                    rule.interfaceTypeMatch = .any
                #endif
            }
            #if !os(tvOS)
                rule.ssidMatch = value.ssids.isEmpty ? nil : value.ssids
            #endif
            return rule
        }
    }

    private func emitStatuses() {
        for (id, manager) in managers {
            sequence &+= 1
            let event = VPNStatusEvent(managerID: id, sequence: sequence, status: Self.map(manager.connection.status))
            for continuation in continuations.values {
                continuation.yield(event)
            }
        }
    }

    fileprivate static func map(_ status: NEVPNStatus) -> VPNStatus {
        switch status {
        case .invalid: .invalid
        case .disconnected: .disconnected
        case .connecting: .connecting
        case .connected: .connected
        case .reasserting: .reasserting
        case .disconnecting: .disconnecting
        @unknown default: .invalid
        }
    }
}

/// One restart's confirmation: every status change re-reads the restarted manager's own connection until
/// `StartObservation` decides, and the gate takes that first decision only.
@MainActor
private final class StartWatch {
    let gate = SingleResume<Void>()
    private let connection: NEVPNConnection
    private var observation = StartObservation()
    private var observer: any NSObjectProtocol?

    init(connection: NEVPNConnection) {
        self.connection = connection
    }

    /// Any status notification triggers a read, so a change is never lost to which connection object NE names in it.
    func arm() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.inspect() }
        }
    }

    func inspect() {
        switch observation.observe(NetworkExtensionManagerSystem.map(connection.status)) {
        case .connected?: gate.finish(.success(()))
        case .failed?: gate.finish(.failure(NEVPNError(.connectionFailed)))
        case nil: break
        }
    }

    func end() {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
        observer = nil
    }
}
