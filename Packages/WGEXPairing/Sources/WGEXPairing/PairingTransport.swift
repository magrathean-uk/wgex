// SPDX-License-Identifier: MIT
import Foundation

/// Transports exchange frame bodies and enforce the same 64 KiB bound.
public protocol PairingTransport: Sendable {
    func send(_ message: Data) async throws
    func receive() async throws -> Data
    func close() async
}

/// Paired, bounded endpoints. Faults operate on complete wire frames, including the length prefix.
public actor InMemoryPairingTransport: PairingTransport {
    public enum Fault: Sendable {
        case pass, drop, delay, reorder, substitute(Data)
    }

    public typealias Hook = @Sendable (Data) -> Fault
    private let inbox: MemoryInbox
    private let outbox: MemoryInbox
    private var hook: Hook = { _ in .pass }
    private var delayed: [Data] = []
    private var held: Data?
    private var closed = false

    private init(inbox: MemoryInbox, outbox: MemoryInbox) {
        self.inbox = inbox; self.outbox = outbox
    }

    public static func pair() -> (InMemoryPairingTransport, InMemoryPairingTransport) {
        let first = MemoryInbox(); let second = MemoryInbox()
        return (Self(inbox: first, outbox: second), Self(inbox: second, outbox: first))
    }

    public func setHook(_ hook: @escaping Hook) {
        self.hook = hook
    }

    public func send(_ message: Data) async throws {
        guard !closed else { throw PairingError.closed }
        let frame: Data
        do { frame = try PairingFrame.encode(message) }
        catch { await close(); throw error }
        switch hook(frame) {
        case .pass: try await deliver(frame)
        case .drop: break
        case .delay:
            guard delayed.count < 16 else { await close(); throw PairingError.frameOverflow }
            delayed.append(frame)
        case .reorder:
            if let previous = held {
                held = nil; try await deliver(frame); try await deliver(previous)
            } else {
                held = frame
            }
        case let .substitute(replacement): try await deliver(replacement)
        }
    }

    public func flushDelayed(reversed: Bool = false) async throws {
        let frames = reversed ? Array(delayed.reversed()) : delayed
        delayed.removeAll()
        for frame in frames {
            try await deliver(frame)
        }
    }

    public func receive() async throws -> Data {
        do { return try await PairingFrame.decode(inbox.receive()) }
        catch { await close(); throw error }
    }

    public func close() async {
        closed = true; delayed.removeAll(); held = nil
        await inbox.close(); await outbox.close()
    }

    private func deliver(_ frame: Data) async throws {
        do { try await outbox.push(frame) }
        catch { await close(); throw error }
    }
}

private actor MemoryInbox {
    private var queue: [Data] = []
    private var waiter: CheckedContinuation<Data, any Error>?
    private var closed = false

    func push(_ data: Data) throws {
        guard !closed else { throw PairingError.closed }
        guard data.count <= PairingFrame.maximumLength + 4, queue.count < 16 else { throw PairingError.frameOverflow }
        if let pending = waiter {
            waiter = nil; pending.resume(returning: data)
        } else {
            queue.append(data)
        }
    }

    func receive() async throws -> Data {
        try Task.checkCancellation()
        if !queue.isEmpty {
            return queue.removeFirst()
        }
        guard !closed else { throw PairingError.closed }
        guard waiter == nil else { throw PairingError.invalidTransition }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { waiter = $0 }
        } onCancel: { Task { await self.close() } }
    }

    func close() {
        closed = true
        waiter?.resume(throwing: PairingError.closed); waiter = nil
    }
}
