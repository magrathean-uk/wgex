// SPDX-License-Identifier: MIT
import Foundation
import Network

/// Discovery returns opaque endpoints, never session IDs or invitations.
public struct PairingDiscoveredService: Sendable, Hashable {
    public let endpoint: NWEndpoint
    public init(endpoint: NWEndpoint) {
        self.endpoint = endpoint
    }
}

public protocol PairingBrowsing: Sendable {
    func start() async throws -> AsyncThrowingStream<[PairingDiscoveredService], any Error>
    func stop() async
}

public enum PairingBonjourMetadata {
    public static var txtRecord: NWTXTRecord {
        NWTXTRecord(["v": "1"])
    }

    public static func accepts(_ record: NWTXTRecord) -> Bool {
        record == txtRecord
    }
}

/// Listener lifetime is owned by the TV session through PairingAdvertising.
public actor BonjourAdvertiser: PairingAdvertising {
    private let name: String
    private let onConnection: @Sendable (NWPairingTransport) async -> Void
    private var listener: NWListener?

    public init(name: String, onConnection: @escaping @Sendable (NWPairingTransport) async -> Void) {
        self.name = name; self.onConnection = onConnection
    }

    public func start() async throws {
        guard listener == nil else { throw PairingError.invalidTransition }
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.service = NWListener.Service(name: name, type: PairingService.bonjourType, txtRecord: PairingBonjourMetadata.txtRecord)
        let callback = onConnection
        listener.newConnectionHandler = { connection in
            Task {
                let transport = NWPairingTransport(connection: connection)
                do { try await transport.start(); await callback(transport) }
                catch { await transport.close() }
            }
        }
        let updates = AsyncThrowingStream<Void, any Error>.makeStream(bufferingPolicy: .bufferingNewest(1))
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: updates.continuation.yield(()); updates.continuation.finish()
            case .failed: updates.continuation.finish(throwing: PairingError.networkUnavailable)
            case .cancelled: updates.continuation.finish(throwing: PairingError.closed)
            default: break
            }
        }
        listener.start(queue: .global(qos: .userInitiated))
        do {
            try await withTaskCancellationHandler {
                for try await _ in updates.stream {
                    break
                }
                try Task.checkCancellation()
            } onCancel: { listener.cancel() }
            guard self.listener != nil else { throw PairingError.closed }
        } catch { stop(); throw error }
    }

    public func stop() {
        listener?.cancel(); listener = nil
    }
}

public actor BonjourBrowser: PairingBrowsing {
    private var browser: NWBrowser?
    private var continuation: AsyncThrowingStream<[PairingDiscoveredService], any Error>.Continuation?

    public init() {}

    public func start() throws -> AsyncThrowingStream<[PairingDiscoveredService], any Error> {
        guard browser == nil else { throw PairingError.invalidTransition }
        let updates = AsyncThrowingStream<[PairingDiscoveredService], any Error>.makeStream(bufferingPolicy: .bufferingNewest(1))
        continuation = updates.continuation
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: PairingService.bonjourType, domain: nil), using: .tcp)
        self.browser = browser
        browser.browseResultsChangedHandler = { results, _ in
            let accepted = results.compactMap { result -> PairingDiscoveredService? in
                guard case let .bonjour(record) = result.metadata, PairingBonjourMetadata.accepts(record) else { return nil }
                return PairingDiscoveredService(endpoint: result.endpoint)
            }
            updates.continuation.yield(accepted)
        }
        browser.stateUpdateHandler = { state in
            if case .failed = state {
                updates.continuation.finish(throwing: PairingError.networkUnavailable)
            }
        }
        updates.continuation.onTermination = { _ in browser.cancel() }
        browser.start(queue: .global(qos: .userInitiated))
        return updates.stream
    }

    public func stop() {
        browser?.cancel(); browser = nil
        continuation?.finish(); continuation = nil
    }
}
