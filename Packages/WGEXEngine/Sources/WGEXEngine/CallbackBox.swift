// SPDX-License-Identifier: MIT

#if WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
#else
    import CWGEXEngine
#endif
import Foundation
import Synchronization
import WGEXCore
import WGEXEngineInterface

/// Cumulative loss on the bounded callback streams. A slow consumer can read the latest totals.
public struct EngineCallbackDrops: Sendable, Hashable {
    public let logs: UInt64
    public let events: UInt64
}

/// All callback state is independent of actor isolation. The engine owns a strong reference
/// until destroy has drained Go's dispatcher; C receives only an unretained pointer to it.
package final class CallbackBox: Sendable {
    package let logs: AsyncStream<EngineLogLine>
    package let events: AsyncStream<EngineEvent>
    package let drops: AsyncStream<EngineCallbackDrops>
    private let logContinuation: AsyncStream<EngineLogLine>.Continuation
    private let eventContinuation: AsyncStream<EngineEvent>.Continuation
    private let dropContinuation: AsyncStream<EngineCallbackDrops>.Continuation
    private struct State {
        var alive = true
        var logs: UInt64 = 0
        var events: UInt64 = 0
    }

    private let state = Mutex(State())

    package init(capacity: Int = 1024) {
        (logs, logContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(capacity))
        (events, eventContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(capacity))
        (drops, dropContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
    }

    package func finish() {
        state.withLock { $0.alive = false }
        logContinuation.finish()
        eventContinuation.finish()
        dropContinuation.finish()
    }

    private func log(level: Int32, message: String) {
        guard state.withLock({ $0.alive }) else { return }
        let line = EngineLogLine(level: .init(rawValue: level) ?? .error, message: message, date: Date())
        if case .dropped = logContinuation.yield(line) {
            recordDrop(log: true)
        }
    }

    private func event(_ bytes: [UInt8]) {
        guard state.withLock({ $0.alive }), let event = Self.decode(bytes) else { return }
        if case .dropped = eventContinuation.yield(event) {
            recordDrop(log: false)
        }
    }

    private func recordDrop(log: Bool) {
        let sample = state.withLock { state in
            if log {
                state.logs &+= 1
            } else {
                state.events &+= 1
            }
            return EngineCallbackDrops(logs: state.logs, events: state.events)
        }
        dropContinuation.yield(sample)
    }

    /// These closures capture no actor or executor. The byte range is valid only during
    /// the C callback; it is copied before returning. No Task or consumer work runs here.
    package nonisolated static let logTrampoline: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?, Int) -> Void = {
        context, level, message, length in
        guard let rawContext = unsafe context, let rawMessage = unsafe message, length >= 0 else { return }
        // Engine lifetime keeps this box alive, and C promises exactly length readable bytes.
        let box = unsafe Unmanaged<CallbackBox>.fromOpaque(rawContext).takeUnretainedValue()
        let bytes = unsafe UnsafeRawBufferPointer(start: rawMessage, count: length)
        box.log(level: level, message: unsafe String(decoding: bytes, as: UTF8.self))
    }

    package nonisolated static let eventTrampoline: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?, Int) -> Void = {
        context, _, message, length in
        guard let rawContext = unsafe context, let rawMessage = unsafe message, length >= 0 else { return }
        // Same registration and buffer lifetime guarantees as logTrampoline.
        let box = unsafe Unmanaged<CallbackBox>.fromOpaque(rawContext).takeUnretainedValue()
        let bytes = unsafe Array(UnsafeRawBufferPointer(start: rawMessage, count: length))
        box.event(bytes)
    }

    private enum PayloadKeys: String, CodingKey { case kind, peer, at, since, endpoint, event, reason, ok }

    private struct Payload: Decodable {
        let kind: String
        let peer: String?
        let at: String?
        let since: String?
        let endpoint: String?
        let event: String?
        let reason: Int32?
        let transportReason: String?
        let ok: Bool?

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: PayloadKeys.self)
            kind = try container.decode(String.self, forKey: .kind)
            peer = try container.decodeIfPresent(String.self, forKey: .peer)
            at = try container.decodeIfPresent(String.self, forKey: .at)
            since = try container.decodeIfPresent(String.self, forKey: .since)
            endpoint = try container.decodeIfPresent(String.self, forKey: .endpoint)
            event = try container.decodeIfPresent(String.self, forKey: .event)
            reason = try? container.decode(Int32.self, forKey: .reason)
            transportReason = try? container.decode(String.self, forKey: .reason)
            ok = try container.decodeIfPresent(Bool.self, forKey: .ok)
        }
    }

    package static func date(_ value: String?) -> Date? {
        guard let value else { return nil }
        // The complete ISO 8601 strategy accepts RFC 3339 with optional fractional
        // seconds, including Go's nine-digit RFC3339Nano output.
        return try? Date(value, strategy: .iso8601)
    }

    private static func decode(_ bytes: [UInt8]) -> EngineEvent? {
        guard let payload = try? JSONDecoder().decode(Payload.self, from: Data(bytes)) else { return nil }
        switch payload.kind {
        case "handshakeCompleted":
            guard let key = payload.peer.flatMap({ try? PublicKey(base64: $0) }), let at = date(payload.at) else { return nil }
            return .handshakeCompleted(peer: key, at: at)
        case "txWithoutRx":
            return date(payload.since).map { .txWithoutRx(since: $0) }
        case "rx":
            return date(payload.at).map { .rx(at: $0) }
        case "endpointChanged":
            guard let key = payload.peer.flatMap({ try? PublicKey(base64: $0) }),
                  let endpoint = payload.endpoint.flatMap({ try? Endpoint($0) }) else { return nil }
            return .endpointChanged(peer: key, endpoint: endpoint)
        case "engine":
            return lifecycle(payload)
        case "transport":
            return transport(payload)
        default: return nil
        }
    }

    private static func lifecycle(_ payload: Payload) -> EngineEvent? {
        switch payload.event {
        case "deviceClosed": .engine(.deviceClosed(EngineDeviceClosedReason(rawValue: payload.reason ?? 0) ?? .unknown))
        case "configRestored": .engine(.configRestored)
        case "socketsBumped": payload.ok.map { .engine(.socketsBumped(ok: $0)) }
        default: nil
        }
    }

    private static func transport(_ payload: Payload) -> EngineEvent? {
        switch payload.event {
        case "carrierConnected": .transport(.carrierConnected)
        case "carrierDisconnected": .transport(.carrierDisconnected(reason: payload.transportReason ?? ""))
        case "authFailed": .transport(.authFailed)
        case "certificateMismatch": .transport(.certificateMismatch)
        default: nil
        }
    }
}
