// SPDX-License-Identifier: MIT
import Foundation
import Network

/// TCP framing. One reader and one writer may run concurrently; overlapping reads/writes are rejected.
public actor NWPairingTransport: PairingTransport {
    private let connection: NWConnection
    private var started = false
    private var ready = false
    private var closed = false
    private var reading = false
    private var writing = false

    /// Accepts an unstarted connection, including one delivered by NWListener.
    public init(connection: NWConnection) {
        self.connection = connection
    }

    public static func connect(to endpoint: NWEndpoint) async throws -> NWPairingTransport {
        let transport = NWPairingTransport(connection: NWConnection(to: endpoint, using: .tcp))
        try await transport.start()
        return transport
    }

    public func start() async throws {
        guard !started, !closed else { throw PairingError.invalidTransition }
        started = true
        let updates = AsyncThrowingStream<Void, any Error>.makeStream(bufferingPolicy: .bufferingNewest(1))
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: updates.continuation.yield(()); updates.continuation.finish()
            case .failed: updates.continuation.finish(throwing: PairingError.networkUnavailable)
            case .cancelled: updates.continuation.finish(throwing: PairingError.closed)
            default: break
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
        let connection = connection
        do {
            try await withTaskCancellationHandler {
                for try await _ in updates.stream {
                    break
                }
                try Task.checkCancellation()
            } onCancel: { connection.cancel() }
            guard !closed else { throw PairingError.closed }
            ready = true
        } catch { close(); throw error }
    }

    public func send(_ message: Data) async throws {
        guard ready, !closed else { throw PairingError.closed }
        guard !writing else { throw PairingError.invalidTransition }
        writing = true; defer { writing = false }
        do {
            let frame = try PairingFrame.encode(message)
            let connection = connection
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    connection.send(content: frame, completion: .contentProcessed { error in
                        if error != nil {
                            continuation.resume(throwing: PairingError.networkUnavailable)
                        } else {
                            continuation.resume()
                        }
                    })
                }
                try Task.checkCancellation()
            } onCancel: { connection.cancel() }
        } catch { close(); throw error }
    }

    public func receive() async throws -> Data {
        guard ready, !closed else { throw PairingError.closed }
        guard !reading else { throw PairingError.invalidTransition }
        reading = true; defer { reading = false }
        do {
            let header = try await readExactly(4)
            let length = header.reduce(0) { $0 << 8 | Int($1) }
            guard length > 0, length <= PairingFrame.maximumLength else { throw PairingError.frameOverflow }
            return try await readExactly(length)
        } catch { close(); throw error }
    }

    public func close() {
        closed = true; ready = false; connection.cancel()
    }

    private func readExactly(_ count: Int) async throws -> Data {
        var result = Data()
        while result.count < count {
            let remaining = count - result.count
            let connection = connection
            let chunk: Data = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, complete, error in
                        if error != nil {
                            continuation.resume(throwing: PairingError.networkUnavailable)
                        } else if let data, !data.isEmpty {
                            continuation.resume(returning: data)
                        } else {
                            continuation.resume(throwing: complete ? PairingError.truncatedFrame : .closed)
                        }
                    }
                }
            } onCancel: { connection.cancel() }
            try Task.checkCancellation()
            guard !closed else { throw PairingError.closed }
            result.append(chunk)
        }
        return result
    }
}
