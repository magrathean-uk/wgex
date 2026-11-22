// SPDX-License-Identifier: MIT

import Foundation

/// Reply to ``Request/hello(clientVersion:clientBuild:)``.
public struct HelloReply: Codable, Sendable, Hashable {
    /// Daemon marketing version.
    public var daemonVersion: String
    /// Daemon build number.
    public var daemonBuild: Int
    /// Wire protocol version.
    public var protocolVersion: Int
    /// Oldest client build the daemon accepts.
    public var minimumClientBuild: Int

    /// Identity of this daemon process, independent of its build or persisted sequence range.
    public var instanceID: UUID

    /// Creates a reply.
    public init(daemonVersion: String, daemonBuild: Int, protocolVersion: Int, minimumClientBuild: Int, instanceID: UUID = UUID()) {
        self.instanceID = instanceID
        self.daemonVersion = daemonVersion
        self.daemonBuild = daemonBuild
        self.protocolVersion = protocolVersion
        self.minimumClientBuild = minimumClientBuild
    }
}
