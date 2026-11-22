// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import WGEXCore

/// Keyed metadata only; callback secret bytes retain their separate binary layout.
package struct SecretsRequest: Codable, Sendable {
    package let profileID: UUID
}

/// A refusal uses a keyed plist; successful replies start with SecretsWireLayout.version (1).
package struct SecretsRefusal: Codable, Sendable {
    package let error: DaemonError
}

package enum SecretsCallback {
    package static let budget: Duration = .seconds(5)

    /// Fixed public categories only; no adapter descriptions or private error payloads.
    package static func failure(_ error: any Error) -> DaemonFailure {
        let kind: DaemonFailure.Code = switch error {
        case let failure as DaemonFailure: failure.kind
        case let wire as DaemonError: DaemonFailure.classify(wire)
        case is CancellationError: .tunnelCancelled
        default: .secretsUnavailable
        }
        // This classifier is used only on the daemon-to-app secrets callback leg.
        let handoffKind: DaemonFailure.Code = kind == .disconnected ? .secretsHandoffDisconnected : kind
        return DaemonFailure(wire: DaemonFailure.catalog[handoffKind]?.wireError ?? .secretsUnavailable)
    }

    package static func refusal(_ error: any Error) -> Data {
        // Fixed, small error DTO; no secret bytes enter Codable.
        (try? WireCodec.encode(SecretsRefusal(error: failure(error).wireError()))) ?? Data()
    }

    package static func response(_ bytes: Data) throws -> Data {
        do {
            guard bytes.count <= DaemonDispatcher.maximumPayloadSize else { throw DaemonError.messageTooLarge(bytes.count) }
            guard !bytes.isEmpty else { throw DaemonError.secretsUnavailable }
            if bytes.starts(with: Data("bplist".utf8)) {
                throw try DaemonFailure(wire: WireCodec.decode(SecretsRefusal.self, from: bytes).error)
            }
            return bytes
        } catch {
            SecretsWireLayout.wipeReceived(bytes)
            throw failure(error)
        }
    }

    /// Bounds the entire dispatcher handoff budget, including an unresponsive injected callback.
    /// The producer is unstructured because a remote callback need not honour cancellation.
    package static func wait(
        profileID: UUID, callback: @escaping @Sendable (UUID) async throws -> Data,
        clock: XPCClock, remaining: Duration,
    ) async throws -> Data {
        let producer = Mutex<Task<Void, Never>?>(nil)
        defer { producer.withLock { $0?.cancel(); $0 = nil } }
        return try await RequestDeadline(clock: clock).wait(
            for: .status, budget: remaining, timeoutError: .tunnel(.timedOut), discardLateReply: SecretsWireLayout.wipeReceived,
            begin: { finish in
                producer.withLock { task in
                    task = Task {
                        do { try await finish(.success(callback(profileID))) }
                        catch { finish(.failure(error)) }
                    }
                }
            }, interrupted: {},
        )
    }
}
