// SPDX-License-Identifier: MIT
#if os(macOS)
    import Foundation
    import Synchronization

    /// Objective-C interface; secret bytes always use a separate argument.
    @objc public protocol WGEXDaemonXPC {
        func send(_ envelope: Data, reply: @escaping @Sendable (Data) -> Void)
        func start(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void)
        func setStartBeforeLogin(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void)
        func subscribe(_ envelope: Data, reply: @escaping @Sendable (Data) -> Void)
        func armOnDemand(_ envelope: Data, secrets: Data, reply: @escaping @Sendable (Data) -> Void)
    }

    @objc public protocol WGEXClientEventsXPC {
        func event(_ data: Data)
        func provideSecrets(_ request: Data, reply: @escaping @Sendable (Data) -> Void)
    }

    /// Error handlers and reply blocks can race. Exactly one resumes the continuation.
    package final class XPCReplyOnce: Sendable {
        private let continuation: Mutex<CheckedContinuation<Data, any Error>?>

        package init(_ continuation: CheckedContinuation<Data, any Error>) {
            self.continuation = Mutex(continuation)
        }

        package func finish(_ result: Result<Data, any Error>) {
            let pending = continuation.withLock { value in
                let pending = value
                value = nil
                return pending
            }
            pending?.resume(with: result)
        }
    }

    package final class ClientEventsExport: NSObject, WGEXClientEventsXPC, Sendable {
        private let callbacks: XPCClientCallbacks
        private let pump: OrderedEventPump

        package init(callbacks: XPCClientCallbacks) {
            self.callbacks = callbacks
            pump = OrderedEventPump(deliver: callbacks.event)
        }

        package func event(_ data: Data) {
            guard data.count <= DaemonDispatcher.maximumPayloadSize else { return }
            pump.enqueue(data)
        }

        package static func decodeSecretsRequest(_ bytes: Data) throws -> UUID {
            try WireCodec.decode(SecretsRequest.self, from: bytes).profileID
        }

        package func provideSecrets(_ request: Data, reply: @escaping @Sendable (Data) -> Void) {
            Task {
                do {
                    let id = try Self.decodeSecretsRequest(request)
                    var bytes = try await callbacks.provideSecrets(id)
                    defer { bytes.resetBytes(in: 0 ..< bytes.count) }
                    guard bytes.count <= DaemonDispatcher.maximumPayloadSize else { throw DaemonError.messageTooLarge(bytes.count) }
                    guard !bytes.isEmpty else { throw DaemonError.secretsUnavailable }
                    reply(bytes)
                } catch { reply(SecretsCallback.refusal(error)) }
            }
        }
    }
#endif
