// SPDX-License-Identifier: MIT
import Foundation

public protocol LoginSessionMonitoring: Sendable {
    /// nil means loginwindow/no console user; root is never treated as the owner's session.
    func start() async throws -> AsyncStream<UInt32?>
    func stop() async
}

public struct LoginSessionMonitorModel: Sendable {
    public private(set) var consoleUID: UInt32?
    public init(consoleUID: UInt32? = nil) {
        self.consoleUID = consoleUID
    }

    public mutating func receive(_ uid: UInt32?, ownerUID: UInt32, startBeforeLogin: Bool) -> Bool {
        let next = uid == 0 ? nil : uid
        defer { consoleUID = next }
        return !startBeforeLogin && next != ownerUID
    }
}
