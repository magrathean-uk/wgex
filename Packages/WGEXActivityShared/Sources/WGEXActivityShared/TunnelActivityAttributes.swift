// SPDX-License-Identifier: MIT

#if canImport(ActivityKit) && os(iOS)
    import ActivityKit
    import Foundation
    import WGEXCore

    /// Live Activity attributes shared by the iOS app and the Live Activity extension.
    public struct TunnelActivityAttributes: ActivityAttributes {
        /// Dynamic state shown in the Live Activity.
        public struct ContentState: Codable, Hashable, Sendable {
            /// Protection state.
            public var protection: ProtectionState
            /// When the tunnel became active.
            public var connectedSince: Date?

            /// Creates a state.
            public init(protection: ProtectionState, connectedSince: Date?) {
                self.protection = protection
                self.connectedSince = connectedSince
            }
        }

        /// Profile display name.
        public var profileName: String

        /// Creates attributes.
        public init(profileName: String) {
            self.profileName = profileName
        }
    }
#endif
